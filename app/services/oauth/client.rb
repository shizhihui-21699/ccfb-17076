module OAuth
  # OAuth2 客户端：负责授权 URL、code 换 token。密钥只从环境变量取。
  class Client
    attr_reader :provider

    def initialize(provider, transport: HttpTransport)
      @provider = provider.to_s
      @config = Rails.configuration.x.oauth_providers.fetch(@provider) do
        raise ProviderError, "unknown provider #{@provider}"
      end
      @transport = transport
    end

    def client_id
      ENV.fetch("#{@provider.upcase}_CLIENT_ID") { "mock-#{@provider}-client-id" }
    end

    def client_secret
      # mock provider 不校验 secret；真实环境必须由环境变量提供
      ENV["#{@provider.upcase}_CLIENT_SECRET"]
    end

    def authorize_url(state:, redirect_uri:, mode: 'login')
      params = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        response_type: 'code',
        state: state,
        scope: Array(@config[:scopes]).join(' '),
        access_type: 'offline',
        # 状态随 state 一起由会话保管；mock 服务器会原样回传以便测试
        mode: mode
      }
      "#{endpoint_url(:authorize_url)}?#{URI.encode_www_form(params)}"
    end

    def exchange_code(code, redirect_uri:)
      form = {
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirect_uri,
        client_id: client_id
      }
      form[:client_secret] = client_secret if client_secret
      res = @transport.post_form(endpoint_url(:token_url), form: form,
                                                        headers: { 'Accept' => 'application/json' })
      raise ProviderError, "token endpoint returned #{res.status}" unless (200..299).cover?(res.status)
      token = res.json
      raise ProviderError, 'token endpoint returned no access_token' if token['access_token'].blank?
      token
    end

    private

    # 开发/测试环境由 MockUrlOverride 把外部地址换成本机 mock 路由
    def endpoint_url(key)
      OAuth::MockUrlOverride.fetch(@provider, key, @config.fetch(key))
    end
  end
end
