require 'base64'
require 'openssl'
require 'json'

module OAuth
  # 最小 RS256 JWT 校验器（OIDC id_token 用）。不引入外部 gem。
  # 校验：签名（按 kid 从 JWKS 取公钥）、iss、aud、exp、nbf、iat。
  class JwtVerifier
    class ClaimError < StandardError; end

    def self.decode_unverified(id_token)
      _header, payload, _signature = id_token.split('.')
      JSON.parse(base64url_decode(payload))
    end

    def self.verify(id_token, jwks_url:, issuer:, audience:, transport: HttpTransport)
      header_segment, payload_segment, signature_segment = id_token.split('.')
      raise ClaimError, 'malformed JWT' unless signature_segment

      header = JSON.parse(base64url_decode(header_segment))
      raise ClaimError, 'unsupported alg' unless header['alg'] == 'RS256'

      jwk = fetch_jwks(jwks_url, transport).find { |k| k['kid'] == header['kid'] }
      raise ClaimError, "no matching JWK for kid=#{header['kid']}" unless jwk

      public_key = jwk_to_rsa(jwk)
      signing_input = "#{header_segment}.#{payload_segment}"
      signature = base64url_decode(signature_segment)
      unless public_key.verify(OpenSSL::Digest::SHA256.new, signature, signing_input)
        raise ClaimError, 'signature verification failed'
      end

      claims = JSON.parse(base64url_decode(payload_segment))
      now = Time.current.to_i
      raise ClaimError, 'token expired' if claims['exp'] && claims['exp'] < now
      raise ClaimError, 'token not yet valid (nbf)' if claims['nbf'] && claims['nbf'] > now
      raise ClaimError, 'token issued in the future (iat)' if claims['iat'] && claims['iat'] > now + 60
      verify_issuer(claims['iss'], issuer)
      verify_audience(claims['aud'], audience)
      claims
    end

    def self.base64url_decode(str)
      str = str.tr('-_', '+/')
      str += '=' * ((4 - str.length % 4) % 4)
      Base64.decode64(str)
    end

    def self.base64url_encode(str)
      Base64.strict_encode64(str).tr('+/', '-_').delete('=')
    end

    def self.fetch_jwks(jwks_url, transport)
      transport.get(jwks_url).json.fetch('keys')
    rescue StandardError => e
      raise ClaimError, "JWKS fetch failed: #{e.message}"
    end

    def self.verify_issuer(actual, expected)
      ok = Array(expected).any? do |rule|
        rule.is_a?(Regexp) ? rule.match?(actual.to_s) : rule == actual
      end
      raise ClaimError, "bad issuer: #{actual}" unless ok
    end

    def self.verify_audience(actual, expected)
      aud = Array(actual)
      ok = aud.include?(expected) || (actual.is_a?(Hash) && actual['aud'] == expected)
      raise ClaimError, "bad audience: #{actual.inspect}" unless ok
    end

    # 仅支持 RSA 系列 JWK（RSA-PSS 之外的常见 n/e 形式）
    def self.jwk_to_rsa(jwk)
      raise ClaimError, "unsupported JWK kty=#{jwk['kty']}" unless jwk['kty'] == 'RSA'
      n = OpenSSL::BN.new(base64url_decode(jwk['n']), 2)
      e = OpenSSL::BN.new(base64url_decode(jwk['e']), 2)
      # Ruby 2.6 的 OpenSSL::PKey::RSA.new 不支持直接传 n/e，用 set_key
      rsa = OpenSSL::PKey::RSA.new
      rsa.set_key(n, e, nil)
      rsa
    end
  end
end
