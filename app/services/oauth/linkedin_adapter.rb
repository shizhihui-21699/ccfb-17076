module OAuth
  # LinkedIn：r_emailaddress 返回的邮箱没有验证标记字段 → unknown。
  class LinkedinAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      profile_data = get_json('https://api.linkedin.com/v2/me', access_token)
      email_data =
        begin
          get_json(url_for(:userinfo_url), access_token,
                   query: { q: 'members', projection: '(elements*(handle~))' })
        rescue OAuth::TransportError
          {}
        end
      email = email_data.dig('elements', 0, 'handle~', 'emailAddress')
      uid = profile_data['id'] || profile_data['sub']
      profile(uid: uid, email: email,
              email_verification: 'unknown',
              name: [profile_data['localizedFirstName'],
                     profile_data['localizedLastName']].compact.join(' ').presence,
              raw: { profile: profile_data, email: email_data })
    end
  end
end
