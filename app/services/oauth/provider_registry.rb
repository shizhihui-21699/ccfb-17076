module OAuth
  # provider 字符串 → 适配器实例的唯一入口
  class ProviderRegistry
    class UnknownProvider < StandardError; end

    def self.adapter_for(provider, transport: HttpTransport)
      cfg = Rails.configuration.x.oauth_providers[provider.to_s]
      raise UnknownProvider, provider unless cfg
      klass = OAuth.const_get(cfg[:adapter])
      klass.new(provider.to_s, transport: transport)
    end

    def self.known?(provider)
      Rails.configuration.x.oauth_providers.key?(provider.to_s)
    end

    def self.names
      Rails.configuration.x.oauth_providers.keys.map(&:to_s)
    end
  end
end
