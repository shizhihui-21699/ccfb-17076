# frozen_string_literal: true

require_relative "../auth_info"

module OAuthLogin
  module Adapters
    # Base class for provider adapters.
    #
    # An adapter's only job is to take the provider's raw response (parsed ID
    # token claims and/or user-info API payload) and emit an AuthInfo whose
    # +email_status+ faithfully represents what THIS provider actually verified.
    #
    # Hard rule: when in doubt about whether a provider verified an email, the
    # adapter must return +:not_provided+ (or +:unverified+ if the provider
    # explicitly says unverified) -- never +:verified+.
    class Base
      class << self
        def provider_name
          name.split("::").last.gsub(/Adapter\z/, "").downcase
        end
      end

      def provider_name
        self.class.provider_name
      end

      # @param payload [Hash] normalized provider data. Adapters accept the
      #   raw shapes they document in their own class comments.
      # @return [AuthInfo]
      def build(payload)
        raise NotImplementedError, "#{self.class}#build"
      end

      protected

      def auth_info(uid:, email:, email_status:, raw:, metadata: {})
        AuthInfo.new(
          provider: provider_name, uid: uid, email: email,
          email_status: email_status, raw: raw, metadata: metadata
        )
      end

      # The OIDC "email_verified" claim is inconsistently typed across issuers:
      # Google returns a real boolean, Apple/Azure return the strings "true"/
      # "false", Azure v2 sometimes returns it only for managed accounts.
      def truthy_verified_claim?(value)
        return true if value == true
        return false if value == false
        value.is_a?(String) && value.casecmp("true").zero?
      end
    end
  end
end
