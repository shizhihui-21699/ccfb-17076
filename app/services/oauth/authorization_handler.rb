module OAuth
  # 整个授权往返的编排：state 防 CSRF、code 换 token、适配器取资料。
  # controller 只负责会话/重定向，所有协议细节在这里。
  class AuthorizationHandler
    STATE_SESSION_KEY = :oauth_state
    MODE_SESSION_KEY = :oauth_mode

    class StateMismatch < StandardError; end

    def self.start_session!(session, mode:)
      state = SecureRandom.urlsafe_base64(32)
      session[STATE_SESSION_KEY] = { 'state' => state, 'mode' => mode,
                                     'at' => Time.current.to_i }
      session[MODE_SESSION_KEY] = mode
      state
    end

    def self.valid_state?(session, given)
      stored = session[STATE_SESSION_KEY]
      return false unless stored && given.is_a?(String)
      # 10 分钟有效期，防 state 重放窗口过长
      fresh = Time.current.to_i - stored['at'].to_i < 600
      fresh && ActiveSupport::SecurityUtils.secure_compare(stored['state'], given)
    end

    def self.consume_state!(session, given)
      ok = valid_state?(session, given)
      session.delete(STATE_SESSION_KEY)
      raise StateMismatch, 'oauth state mismatch' unless ok
      ok
    end

    def initialize(provider, transport: HttpTransport)
      @provider = provider
      @transport = transport
    end

    def authorize_url(state:, redirect_uri:, mode:)
      Client.new(@provider, transport: @transport)
            .authorize_url(state: state, redirect_uri: redirect_uri, mode: mode)
    end

    def fetch_profile(code:, redirect_uri:)
      client = Client.new(@provider, transport: @transport)
      token = client.exchange_code(code, redirect_uri: redirect_uri)
      adapter = ProviderRegistry.adapter_for(@provider, transport: @transport)
      adapter.fetch_profile(access_token: token['access_token'],
                            id_token: token['id_token'])
    end
  end
end
