require_relative 'boot'

require 'rails'
# 手搓骨架：只加载实际用到的 railtie，避免 asset pipeline / action_mailbox 等
require 'active_record/railtie'
require 'action_controller/railtie'
require 'action_mailer/railtie'
require 'rails/test_unit/railtie'

module OauthGuard
  class Application < Rails::Application
    config.load_defaults 6.0
    config.eager_load = false
    config.root = File.expand_path('..', __dir__)
    config.secret_key_base = ENV.fetch('SECRET_KEY_BASE', 'x' * 128)

    config.hosts.clear

    # 本机 LibreSSL 不支持 AES-GCM（见本地环境备忘），探测后回退 CBC cookie 加密
    begin
      cipher = OpenSSL::Cipher.new('aes-256-gcm')
      cipher.encrypt
      cipher.key = SecureRandom.bytes(32)
      cipher.iv = SecureRandom.bytes(12)
      cipher.auth_data = ''
      cipher.final
      config.action_dispatch.use_authenticated_cookie_encryption = true
    rescue OpenSSL::Cipher::CipherError
      config.action_dispatch.use_authenticated_cookie_encryption = false
    end

    config.action_controller.allow_forgery_protection = true

    config.action_mailer.delivery_method = :test
    config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }

    config.time_zone = 'UTC'

    # 每个 provider 的密钥从环境变量读取，禁止入库；config/providers.yml 只存非敏感配置
    config.x.oauth_providers = YAML.safe_load(
      File.read(File.expand_path('providers.yml', __dir__)),
      permitted_classes: [Symbol]
    ).with_indifferent_access
  end
end
