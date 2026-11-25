module OAuth
  # Google OIDC：id_token/userinfo 带 email_verified 布尔/字符串。
  # 有明确标记 → 按标记；标记缺失/无法解析 → unknown（按未验证处理）。
  class GoogleAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      claims =
        if id_token
          JwtVerifier.verify(
            id_token,
            jwks_url: url_for(:jwks_url),
            issuer: %w[https://accounts.google.com accounts.google.com],
            audience: ENV.fetch('GOOGLE_CLIENT_ID', 'mock-google-client-id'),
            transport: transport
          )
        else
          get_json(url_for(:userinfo_url), access_token)
        end

      email = claims['email']
      verification =
        if claims.key?('email_verified')
          truthy_flag?(claims['email_verified']) ? 'verified' : 'unverified'
        else
          'unknown'
        end
      profile(uid: claims['sub'], email: email, email_verification: verification,
              name: claims['name'], raw: claims)
    end
  end
end
