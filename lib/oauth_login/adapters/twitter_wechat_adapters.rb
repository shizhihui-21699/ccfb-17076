# frozen_string_literal: true

require_relative "base"

module OAuthLogin
  module Adapters
    # X / Twitter OAuth (v1.1 account/verify_credentials or v2 users/me).
    #
    # Email is only returned when the app is permissioned for it AND the user
    # has an address on file. Neither API version tells the consuming app
    # whether the email was verified, so every address comes out
    # +:not_provided+. v2 uses an "id" string; v1 uses a numeric "id".
    class TwitterAdapter < Base
      def build(payload)
        payload = stringify(payload["data"] || payload)

        status = payload["email"] ? :not_provided : :not_requested

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

    # WeChat Open Platform (sns/userinfo).
    #
    # WeChat identities have no email concept at all: the payload carries
    # openid/unionid plus nickname/avatar. AuthInfo therefore always has
    # email_status +:not_requested+ and email? == false. Such an identity can
    # only ever attach to an already-authenticated account -- it can never be
    # used to match into an existing account by email (there is nothing to
    # match on), which the login service enforces.
    class WechatAdapter < Base
      def build(payload)
        payload = stringify(payload)

        auth_info(
          uid: payload["unionid"] || payload.fetch("openid"),
          email: nil,
          email_status: :not_requested,
          raw: payload,
          metadata: { "openid" => payload["openid"] }
        )
      end

      private

      def stringify(hash)
        hash.each_with_object({}) { |(k, v), memo| memo[k.to_s] = v }
      end
    end
  end
end
