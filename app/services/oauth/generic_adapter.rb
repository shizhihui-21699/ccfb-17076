module OAuth
  # 通用/自建 OAuth2 平台：只要协议里没有可信的验证标记，一律 unknown。
  # 这是兜底纪律——新接入一家平台时，默认它不验证邮箱。
  class GenericAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      data = get_json(url_for(:userinfo_url), access_token)
      profile(uid: data['sub'] || data['id'] || data['user_id'],
              email: data['email'],
              email_verification: 'unknown',
              name: data['name'], raw: data)
    end
  end
end
