# frozen_string_literal: true

require_relative "base"

module OAuthLogin
  module Adapters
    # Facebook Login (Graph API /me payload).
    #
    # Facebook historically returns an "email" field but exposes NO flag that
    # tells a third-party app whether the address was verified. (Facebook
    # verifies accounts internally, but the Graph response does not certify the
    # mailbox, and attackers have repeatedly registered accounts with arbitrary
    # email strings.) So no matter what the payload says, we encode
    # +:not_provided+ and force our own out-of-band verification before any
    # merge. This is the exact class of provider behind the reported incident.
    class FacebookAdapter < Base
      def build(payload)
        payload = stringify(payload)

        status = payload.key?("email") ? :not_provided : :not_requested

        auth_info(
          uid: payload.fetch("id").to_s,
          email: payload["email"],
          email_status: status,
          raw: payload
        )
      end

      private

      def stringify(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_s] = v }
      end
    end
  end
end
