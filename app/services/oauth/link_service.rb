module OAuth
  # 已登录用户在账号设置页主动绑定第三方身份。
  # 与 LoginService 的区别：这里有已认证的会话，持有人确认即生效；
  # 但 (provider, uid) 若已属于别人，一律拒绝（不能用绑定流程抢身份）。
  class LinkService
    Result = Struct.new(:success, :identity, :error, keyword_init: true) do
      def success?
        success
      end
    end

    def self.call(current_user, profile)
      new(current_user, profile).call
    end

    def initialize(current_user, profile)
      @user = current_user
      @profile = profile
    end

    def call
      existing = Identity.find_by(provider: @profile.provider,
                                  provider_uid: @profile.uid)
      if existing && existing.user_id != @user.id
        return Result.new(success: false, identity: nil,
                          error: '该第三方身份已绑定其他账号')
      end

      identity = existing || @user.identities.build(provider: @profile.provider,
                                                    provider_uid: @profile.uid)
      identity.provider_email = @profile.email
      identity.email_verification = @profile.email_verification
      identity.status = 'active'
      identity.quarantine_reason = nil
      identity.linked_at = Time.current
      identity.save!
      SecurityEvent.log!('identity_linked', user: @user, identity: identity,
                         provider: identity.provider)
      Result.new(success: true, identity: identity, error: nil)
    end
  end
end
