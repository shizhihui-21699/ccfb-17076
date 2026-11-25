module OAuth
  # 开发/测试环境把外部 provider 地址替换成内置 mock 路由。
  # 独立文件以便 Zeitwerk 自动加载。
  module MockUrlOverride
    def self.fetch(provider, key, original)
      return original unless Rails.env.development? || Rails.env.test?
      case key
      when :authorize_url then "/mock/#{provider}/authorize"
      when :token_url     then "/mock/#{provider}/token"
      when :userinfo_url  then "/mock/#{provider}/userinfo"
      when :emails_url    then "/mock/#{provider}/emails"
      when :jwks_url      then "/mock/#{provider}/jwks"
      when :user_url      then "/mock/#{provider}/userinfo"
      else original
      end
    end
  end
end
