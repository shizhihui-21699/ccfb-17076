# 传输层替身：不发真实 HTTP，直接读 MockOAuthRegistry，
# 让 OauthController 在测试里可以走完整的“授权码 → token → 用户资料”流程。
class MockOAuthTransport
  Response = Struct.new(:status, :body, :headers, keyword_init: true) do
    def json
      JSON.parse(body)
    end
  end

  def initialize(provider, request = nil)
    @provider = provider
    @request = request
    @registry = MockOAuthRegistry.instance
  end

  def get(url, headers: {}, query: nil)
    # JWKS 是公开端点，不需要 bearer token
    if url.include?('/jwks')
      return Response.new(status: 200, body: { keys: [MockOAuthRegistry.jwk] }.to_json)
    end

    token = headers['Authorization'].to_s.sub('Bearer ', '')
    entry = @registry.issued_tokens[token]
    return error(401, 'invalid token') unless entry
    account = @registry.accounts[entry[:provider]][entry[:uid]]
    return error(404, 'no account') unless account

    if url.include?('/userinfo')
      Response.new(status: 200, body: userinfo_body(entry[:provider], account).to_json)
    elsif url.include?('/emails')
      Response.new(status: 200, body: Array(account[:emails]).to_json)
    else
      # LinkedIn 等平台的 profile 端点：返回带 id 的账号结构
      Response.new(status: 200,
                   body: account.merge(id: account[:uid] || account[:id],
                                       sub: account[:uid] || account[:id]).to_json)
    end
  end

  def post_form(url, form:, headers: {})
    code = form[:code]
    entry = @registry.find_by_code(code)
    return error(400, 'invalid code') unless entry
    account = @registry.accounts[entry[:provider]][entry[:uid]]
    access_token = @registry.issue_token(entry[:provider], entry[:uid])
    body = { token_type: 'Bearer', access_token: access_token }
    if %w[google apple microsoft].include?(entry[:provider])
      body[:id_token] = MockOAuthRegistry.signed_jwt(
        id_token_claims(entry[:provider], entry[:uid], account)
      )
    end
    Response.new(status: 200, body: body.to_json)
  end

  private

  def error(status, message)
    Response.new(status: status, body: { error: message }.to_json)
  end

  def userinfo_body(provider, account)
    base = { sub: account[:uid] || account[:id], id: account[:uid] || account[:id],
             name: account[:name], email: account[:email] }
    case provider
    when 'google'
      # Google 给布尔/字符串标记；无标记的场景由测试数据控制
      account.key?(:email_verified) ? base.merge(email_verified: account[:email_verified]) : base
    when 'facebook', 'linkedin', 'generic_oauth2'
      base # 故意不返回任何验证状态
    when 'microsoft'
      base.merge(preferred_username: account[:email]) # 同样无 email_verified
    when 'twitter'
      { data: { id: account[:uid], name: account[:name], username: account[:login] } }
    else
      base
    end
  end

  def id_token_claims(provider, uid, account)
    claims = { sub: uid, iss: issuer_for(provider), aud: audience_for(provider),
               email: account[:email], name: account[:name] }
    case provider
    when 'google'
      # Google 给布尔/字符串标记；无标记的场景由测试数据控制
      claims[:email_verified] = account[:email_verified] if account.key?(:email_verified)
    when 'apple'
      # Apple 的标记是字符串
      claims[:email_verified] = account[:email_verified].to_s if account.key?(:email_verified)
    when 'microsoft'
      # 没有 email_verified
    end
    claims
  end

  def issuer_for(provider)
    {
      'google' => 'https://accounts.google.com',
      'apple' => 'https://appleid.apple.com',
      'microsoft' => 'https://login.microsoftonline.com/tenant-id/v2.0'
    }.fetch(provider)
  end

  def audience_for(provider)
    ENV.fetch("#{provider.upcase}_CLIENT_ID", "mock-#{provider}-client-id")
  end
end
