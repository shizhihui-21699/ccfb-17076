module OAuth
  # Microsoft：v2.0 id_token 一般不带 email_verified（租户管理员可自行验证域名，
  # 但消费账号/M SA 无此保证）。没有明确标记 → unknown。
  # email 可能位于 email / preferred_username，两者都不保证已验证。
  class MicrosoftAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      claims =
        if id_token
          JwtVerifier.verify(
            id_token,
            jwks_url: url_for(:jwks_url),
            issuer: /\Ahttps:\/\/login\.microsoftonline\.com\/.+\//,
            audience: ENV.fetch('MICROSOFT_CLIENT_ID', 'mock-microsoft-client-id'),
            transport: transport
          )
        else
          get_json('https://graph.microsoft.com/oidc/userinfo', access_token)
        end

      email = claims['email'] || claims['preferred_username']
      profile(uid: claims['sub'] || claims['oid'], email: email,
              email_verification: 'unknown', name: claims['name'], raw: claims)
    end
  end
end
