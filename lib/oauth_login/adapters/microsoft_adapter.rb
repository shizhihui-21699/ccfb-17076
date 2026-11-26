# frozen_string_literal: true

require_relative "base"

module OAuthLogin
  module Adapters
    # Microsoft identity platform / Azure AD (OIDC ID token claims).
    #
    # Why this one is dangerous:
    #   * v1 tokens put the address in "upn" (or "email"), v2 tokens use
    #     "preferred_username" -- and preferred_username is explicitly NOT
    #     guaranteed to be a verified mailbox; the docs call it a "user
    #     displayable identifier", usable for routing but not proof.
    #   * "email_verified" exists only for some tenant/account types. For
    #     federated/guest accounts it is routinely absent.
    #
    # Rule implemented here: an address counts as +:verified+ only when there
    # is an explicit truthy "email_verified" claim. Anything derived from
    # upn/preferred_username without that claim is +:not_provided+.
    class MicrosoftAdapter < Base
      def build(claims)
        claims = stringify(claims)

        email = claims["email"] || claims["upn"]
        source = claims.key?("email") || claims.key?("upn") ? "claim" : nil
        if email.nil? && claims["preferred_username"].to_s.include?("@")
          email = claims["preferred_username"]
          source = "preferred_username"
        end

        status =
          if email.nil?
            :not_requested
          elsif truthy_verified_claim?(claims["email_verified"])
            :verified
          else
            :not_provided
          end

        auth_info(
          uid: claims.fetch("sub") || claims.fetch("oid"),
          email: email,
          email_status: status,
          raw: claims,
          metadata: source ? { "email_source" => source } : {}
        )
      end

      private

      def stringify(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_s] = v }
      end
    end
  end
end
