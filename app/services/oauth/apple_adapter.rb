module OAuth
  # Apple Sign In：id_token 的 email_verified 是字符串 "true"/"false"，
  # 另有 is_private_email。私密中继邮箱也是 Apple 控制、可投递的验证邮箱。
  class AppleAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      raise ProviderError, 'Apple requires an id_token' if id_token.blank?
      claims = JwtVerifier.verify(
        id_token,
        jwks_url: url_for(:jwks_url),
        issuer: 'https://appleid.apple.com',
        audience: ENV.fetch('APPLE_CLIENT_ID', 'mock-apple-client-id'),
        transport: transport
      )

      verification =
        if claims.key?('email_verified')
          truthy_flag?(claims['email_verified']) ? 'verified' : 'unverified'
        else
          'unknown'
        end
      profile(uid: claims['sub'], email: claims['email'],
              email_verification: verification, name: claims['name'], raw: claims)
    end
  end
end
