module OAuth
  # GitHub：/user 的 email 字段可能为空，且不带验证状态。
  # 必须调 /user/emails，只接受 verified=true 且 primary=true 的主邮箱；
  # 没有任何已验证邮箱 → 邮箱视为 unknown（照样能登录，但不能据此合并）。
  class GithubAdapter < BaseAdapter
    def fetch_profile(access_token:, id_token: nil)
      user = get_json(url_for(:user_url), access_token)
      emails = get_json(url_for(:emails_url), access_token)
      primary = Array(emails).find { |e| e['primary'] && e['verified'] }
      any_verified = Array(emails).find { |e| e['verified'] }

      email = primary&.dig('email') || user['email']
      verification =
        if primary
          'verified'
        elsif any_verified
          'unverified' # 有已验证邮箱但不是主邮箱，保守处理
        else
          'unknown'
        end
      profile(uid: user['id'], email: email, email_verification: verification,
              name: user['name'] || user['login'], raw: { user: user, emails: emails })
    end
  end
end
