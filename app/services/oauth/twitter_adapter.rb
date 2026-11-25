module OAuth
  # Twitter API v2：users/me 不返回邮箱（申请高级权限才有，且无验证标记）。
  # 拿不到邮箱 → email=nil, unknown；登录可以，合并无从谈起。
  class TwitterAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      data = get_json(url_for(:userinfo_url), access_token,
                      query: { 'user.fields' => 'id,name,username' })
      user = data['data'] || data
      profile(uid: user['id'], email: user['email'],
              email_verification: 'unknown',
              name: user['name'] || user['username'], raw: data)
    end
  end
end
