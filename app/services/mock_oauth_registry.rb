# 仅开发/测试环境加载。模拟各家 OAuth 提供方的行为差异：
# 有的给 email_verified 标记，有的完全不给。
# 测试里数据存内存；开发环境的 server 是独立进程，账号池通过 YAML 文件持久化共享。
class MockOAuthRegistry
  include Singleton

  STORE_PATH = Rails.root.join('tmp', 'mock_oauth_accounts.yml').to_s

  # 结构：provider => { uid => {email:, email_verified:, name:, emails: [...]} }
  attr_reader :accounts, :issued_codes, :issued_tokens

  def reset!
    @accounts = Hash.new { |h, k| h[k] = {} }
    @issued_codes = {}
    @issued_tokens = {}
  end

  # seed 场景下需要连磁盘一起清空；普通进程初始化不能删共享文件
  def reset_all!
    reset!
    File.delete(STORE_PATH) if persisted? && File.exist?(STORE_PATH)
  end

  def initialize
    reset!
    load_from_disk if persisted?
  end

  # 仅开发环境走磁盘共享；测试环境严格内存隔离
  def persisted?
    Rails.env.development?
  end

  def seed(provider, uid, attrs)
    @accounts[provider.to_s][uid.to_s] = attrs.symbolize_keys
    persist! if persisted?
  end

  def find_by_code(code)
    @issued_codes[code]
  end

  def issue_code(provider, uid)
    code = "code-#{SecureRandom.hex(8)}"
    @issued_codes[code] = { provider: provider, uid: uid }
    code
  end

  def issue_token(provider, uid)
    token = "tok-#{SecureRandom.hex(8)}"
    @issued_tokens[token] = { provider: provider, uid: uid }
    token
  end

  def persist!
    File.write(STORE_PATH, YAML.dump(@accounts.deep_stringify_keys))
  end

  def load_from_disk
    raw = YAML.safe_load(File.read(STORE_PATH), permitted_classes: [Symbol]) || {}
    @accounts = Hash.new { |h, k| h[k] = {} }
    raw.each { |provider, h| @accounts[provider] = h.symbolize_keys.transform_values(&:symbolize_keys) }
  rescue StandardError => e
    Rails.logger.warn("[mock-oauth] failed to load store: #{e.message}")
  end

  def self.jwt_signing_key
    # 开发环境密钥持久化，保证不同进程（seed / server）里 JWKS 与签名一致；
    # 测试环境每次进程内生成即可
    @jwt_signing_key ||= begin
      path = Rails.root.join('tmp', 'mock_jwt_key.pem').to_s
      if Rails.env.development? && File.exist?(path)
        OpenSSL::PKey::RSA.new(File.read(path))
      elsif Rails.env.development?
        key = OpenSSL::PKey::RSA.new(2048)
        File.write(path, key.to_pem)
        key
      else
        OpenSSL::PKey::RSA.new(2048)
      end
    end
  end

  def self.jwk
    key = jwt_signing_key
    n = key.public_key.n.to_s(2)
    e = key.public_key.e.to_s(2)
    {
      kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'mock-key-1',
      n: OAuth::JwtVerifier.base64url_encode(n),
      e: OAuth::JwtVerifier.base64url_encode(e)
    }
  end

  def self.signed_jwt(claims)
    header = { alg: 'RS256', typ: 'JWT', kid: 'mock-key-1' }
    now = Time.current.to_i
    payload = { iat: now, nbf: now, exp: now + 3600 }.merge(claims)
    segs = [header, payload].map do |part|
      OAuth::JwtVerifier.base64url_encode(JSON.generate(part))
    end
    signing_input = segs.join('.')
    sig = jwt_signing_key.sign(OpenSSL::Digest::SHA256.new, signing_input)
    "#{signing_input}.#{OAuth::JwtVerifier.base64url_encode(sig)}"
  end
end
