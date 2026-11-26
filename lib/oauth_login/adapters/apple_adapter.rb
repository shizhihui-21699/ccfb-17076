# frozen_string_literal: true

require_relative "base"

module OAuthLogin
  module Adapters
    # Sign in with Apple (OIDC ID token claims).
    #
    # Quirks that matter for security:
    #   * "email_verified" is the STRING "true"/"false", not a boolean.
    #   * Apple only includes the email in the ID token on the FIRST
    #     authorization. On subsequent logins the claim is absent, so a
    #     returning user legitimately produces +:not_requested+ and must be
    #     matched on (provider, uid), never re-matched on email.
    #   * "is_private_email" = "true" means this is Apple's private relay
    #     address. It is still provider-controlled and verified, so it stays
    #     +:verified+ -- but we flag it in metadata so the merge flow can show
    #     the user that the address is a relay (it can never receive our
    #     confirmation mail directly at a real inbox... actually relay
    #     addresses DO forward, but the UI should be honest about it).
    class AppleAdapter < Base
      def build(claims)
        claims = stringify(claims)
        status =
          if !claims.key?("email")
            :not_requested
          elsif truthy_verified_claim?(claims["email_verified"])
            :verified
          elsif claims.key?("email_verified")
            :unverified
          else
            :not_provided
          end

        metadata = {}
        metadata["private_email"] = truthy_verified_claim?(claims["is_private_email"]) if
          claims.key?("is_private_email")

        auth_info(
          uid: claims.fetch("sub"),
          email: claims["email"],
          email_status: status,
          raw: claims,
          metadata: metadata
        )
      end

      private

      def stringify(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_s] = v }
      end
    end
  end
end
