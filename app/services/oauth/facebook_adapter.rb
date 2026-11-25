module OAuth
  # Facebook：Graph API 的 email 字段不附带验证状态。
  # 历史上平台允许未确认邮箱，因此没有验证标记 → unknown，绝不默认 verified。
  class FacebookAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      data = get_json(url_for(:userinfo_url), access_token,
                      query: { fields: 'id,name,email' })
      profile(uid: data['id'], email: data['email'],
              email_verification: 'unknown', name: data['name'], raw: data)
    end
  end
end
