# frozen_string_literal: true

require_relative "base"

module OAuthLogin
  module Adapters
    # Google Sign-In (OIDC ID token claims).
    #
    # Relevant claims:
    #   "sub"            - stable user id (use this, never the email, as uid)
    #   "email"          - present only when the email scope was granted
    #   "email_verified" - boolean; Google only marks this true after the
    #                      mailbox is verified. On some older payloads it
    #                      arrives as the string "true".
    #
    # Google will not let an account keep an unverified email that collides
    # with a verified one, so +email_verified: true+ is trustworthy. Anything
    # missing or false is treated as not verified -- never the reverse.
    class GoogleAdapter < Base
      # @param claims [Hash] decoded/verified ID token claims
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
            # email present but no verification claim: do not assume.
            :not_provided
          end

        auth_info(
          uid: claims.fetch("sub"),
          email: claims["email"],
          email_status: status,
          raw: claims
        )
      end

      private

      def stringify(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_s] = v }
      end
    end
  end
end
