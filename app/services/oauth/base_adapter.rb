module OAuth
  # 适配器基类。子类实现 #build_profile，返回 ProviderProfile。
  # 关键纪律：任何无法确认“邮箱已验证”的情况，都只能返回 unverified/unknown，
  # 绝不允许默认 verified。
  class BaseAdapter
    attr_reader :provider, :transport

    def initialize(provider, transport: HttpTransport)
      @provider = provider
      @transport = transport
    end

    def config
      Rails.configuration.x.oauth_providers.fetch(provider)
    end

    def url_for(key)
      OAuth::MockUrlOverride.fetch(provider, key, config.fetch(key))
    end

    def fetch_profile(access_token:, id_token: nil)
      raise NotImplementedError
    end

    private

    def get_json(url, token, query: nil)
      transport.get(url, query: query,
                         headers: { 'Authorization' => "Bearer #{token}",
                                    'Accept' => 'application/json' }).json
    end

    # 各家表示“验证”的字段值不统一：true / "true" / 1 / "yes"，集中归一
    def truthy_flag?(value)
      return true if value == true
      return false if value == false || value.nil?
      %w[true 1 yes].include?(value.to_s.strip.downcase)
    end

    def profile(uid:, email:, email_verification:, name: nil, raw: {})
      ProviderProfile.new(provider: provider, uid: uid, email: email,
                          email_verification: email_verification, name: name, raw: raw)
    end
  end
end
