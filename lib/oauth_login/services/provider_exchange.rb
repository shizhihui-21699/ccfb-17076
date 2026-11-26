# frozen_string_literal: true

require_relative "../provider_registry"
require_relative "../auth_info"

module OAuthLogin
  module Services
    # Boundary between the transport layer (OmniAuth, raw OAuth exchanges,
    # test fixtures...) and the security logic. Everything entering
    # LoginService must first pass through here so that normalization happens
    # in exactly one place.
    class ProviderExchange
      class << self
        # @param provider [String, Symbol] registered provider name
        # @param payload [Hash] the provider's raw response in the shape its
        #   adapter documents
        # @return [AuthInfo]
        def parse(provider, payload)
          adapter = ProviderRegistry.adapter_for(provider)
          adapter.build(payload)
        end
      end
    end
  end
end
