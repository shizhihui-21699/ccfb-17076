module OAuth
  # 第三方登录的唯一决策入口。
  #
  # 安全规则（对应旧漏洞的修复）：
  #   1. 只按 (provider, provider_uid) 识别已绑定身份；邮箱永远不用于自动归属账号。
  #   2. 已绑定且 active 的身份 → 直接登录；quarantined → 拒绝。
  #   3. 未绑定身份：
  #      a. 站内没有同邮箱账号 → 注册新账号（provider 邮箱是否验证只影响新账号的标记）。
  #      b. 站内已有同邮箱账号 → 绝不自动合并，生成 MergeRequest，等账号持有人确认。
  #         无论 provider 邮箱是否 verified 都走人工确认；verified 只影响风险提示。
  #   4. 对外提示语统一，不泄露“邮箱是否已注册”，防止账号枚举。
  class LoginService
    Result = Struct.new(:outcome, :user, :merge_request, keyword_init: true) do
      def login?
        outcome == :login
      end

      def registered?
        outcome == :registered
      end

      def pending?
        outcome == :merge_pending
      end

      def blocked?
        outcome == :blocked
      end
    end

    def self.call(profile:, ip_address: nil)
      new(profile, ip_address).call
    end

    def initialize(profile, ip_address)
      @profile = profile
      @ip = ip_address
    end

    def call
      identity = Identity.find_by(provider: @profile.provider,
                                  provider_uid: @profile.uid)
      return handle_existing_identity(identity) if identity
      handle_unknown_identity
    end

    private

    def handle_existing_identity(identity)
      if identity.status == 'quarantined'
        SecurityEvent.log!('oauth_login_blocked_quarantined',
                           user: identity.user, identity: identity,
                           provider: identity.provider, ip_address: @ip,
                           detail: identity.quarantine_reason)
        return Result.new(outcome: :blocked, user: nil, merge_request: nil)
      end

      # 顺手刷新 provider 侧资料快照（不改变归属）
      identity.update!(provider_email: @profile.email,
                       email_verification: @profile.email_verification)
      SecurityEvent.log!('oauth_login_success', user: identity.user,
                         identity: identity, provider: identity.provider,
                         ip_address: @ip)
      Result.new(outcome: :login, user: identity.user, merge_request: nil)
    end

    def handle_unknown_identity
      existing = @profile.email && User.find_by_normalized_email(@profile.email)

      if existing
        request = create_merge_request(existing)
        SecurityEvent.log!('oauth_unknown_identity', user: existing,
                           provider: @profile.provider, ip_address: @ip,
                           detail: "uid=#{@profile.uid} email=#{@profile.email} " \
                                   "verification=#{@profile.email_verification}")
        SecurityEvent.log!('merge_request_created', user: existing,
                           merge_request: request, provider: @profile.provider,
                           ip_address: @ip)
        # 邮件失败不得阻断安全决策（合并请求已落库），记录日志后继续
        begin
          MergeNotifierMailer.merge_request_email(request).deliver_now
        rescue StandardError => e
          Rails.logger.error("[merge] notification mail failed: #{e.class}: #{e.message}")
        end
        return Result.new(outcome: :merge_pending, user: nil, merge_request: request)
      end

      register_new_user
    end

    def create_merge_request(target_user)
      MergeRequest.open_for(provider: @profile.provider,
                            provider_uid: @profile.uid,
                            target_user_id: target_user.id) ||
        MergeRequest.create!(
          target_user: target_user,
          provider: @profile.provider,
          provider_uid: @profile.uid,
          provider_email: @profile.email,
          email_verification: @profile.email_verification,
          status: 'pending'
        )
    end

    def register_new_user
      user = User.create!(
        email: @profile.email || generated_placeholder_email,
        email_verified: @profile.provider_email_verified?,
        display_name: @profile.name,
        password_digest: nil
      )
      identity = Identity.create!(
        user: user,
        provider: @profile.provider,
        provider_uid: @profile.uid,
        provider_email: @profile.email,
        email_verification: @profile.email_verification,
        status: 'active',
        linked_at: Time.current
      )
      SecurityEvent.log!('identity_linked', user: user, identity: identity,
                         provider: identity.provider, ip_address: @ip)
      SecurityEvent.log!('oauth_login_success', user: user, identity: identity,
                         provider: identity.provider, ip_address: @ip)
      Result.new(outcome: :registered, user: user, merge_request: nil)
    end

    # provider 不返回邮箱（如 Twitter）时的占位邮箱：随机、不可投递、标记未验证
    def generated_placeholder_email
      "oauth-#{SecureRandom.hex(8)}@#{@profile.provider}.placeholder.invalid"
    end
  end
end
