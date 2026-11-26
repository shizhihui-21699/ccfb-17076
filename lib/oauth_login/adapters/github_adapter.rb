# frozen_string_literal: true

require_relative "base"

module OAuthLogin
  module Adapters
    # GitHub OAuth.
    #
    # GitHub is NOT OIDC: there is no ID token and no verification claim on the
    # /user payload. The /user object's "email" field is whatever the user made
    # public and is often null when users keep their address private.
    #
    # The ONLY place GitHub exposes verification state is the /user/emails
    # endpoint, which returns entries shaped like:
    #   { "email" => "a@example.com", "verified" => true, "primary" => true }
    #
    # Therefore this adapter requires BOTH payloads. If the emails list is
    # missing (scope not granted, integration forgot to fetch it) we return
    # +:not_provided+ rather than trusting the bare /user email.
    class GithubAdapter < Base
      # @param payload [Hash] +user+: parsed /user response,
      #   +emails+: parsed /user/emails response (array)
      def build(payload)
        user = stringify(payload.fetch("user"))
        emails = payload["emails"]

        chosen = choose_email(user, emails)

        status =
          if chosen.nil?
            :not_requested
          elsif chosen["verified"] == true
            :verified
          elsif chosen.key?("verified")
            :unverified
          else
            :not_provided
          end

        auth_info(
          uid: user.fetch("id").to_s,
          email: chosen && chosen["email"],
          email_status: status,
          raw: payload,
          metadata: chosen ? { "primary" => chosen["primary"] } : {}
        )
      end

      private

      # Prefer the primary address from /user/emails; fall back to the public
      # address from /user only when it is present in the verified list.
      def choose_email(user, emails)
        return nil unless emails.is_a?(Array) && !emails.empty?

        normalized = emails.map { |entry| stringify(entry) }
        primary = normalized.find { |entry| entry["primary"] == true }
        return primary if primary

        public_email = user["email"]
        normalized.find { |entry| entry["email"] == public_email } || normalized.first
      end

      def stringify(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_s] = v }
      end
    end
  end
end
