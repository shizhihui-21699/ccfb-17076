# 历史自动合并排查。
#
# 背景：修复前的逻辑“第三方邮箱 == 站内邮箱就自动合并”，
# 对不验证邮箱的平台等于账号接管。本服务把所有现存 identity 按风险分级：
#
#   high   —— 平台不提供/未通过邮箱验证（unknown/unverified），却绑定在一个
#             同邮箱的站内账号上；攻击者可以用同样的伪造邮箱身份重新发起请求。
#   medium —— 平台验证了邮箱，但站内账号本身没有任何其他凭据（无密码、
#             只有这一条 identity），凭据链单一，建议人工复核。
#   low    —— 平台验证了邮箱且账号有独立凭据（密码或其他 identity）。
#
# 模式：
#   audit       只出报告，不改数据（默认、安全）
#   quarantine  把 high 风险 identity 置为 quarantined，登录将被拒绝，
#               并给目标用户生成待确认的 MergeRequest 走正常确认流程
module Audit
  class LegacyMergeAudit
    Finding = Struct.new(:identity, :risk, :reason, keyword_init: true)

    def self.run(mode: 'audit')
      new(mode).run
    end

    def initialize(mode)
      raise ArgumentError, mode unless %w[audit quarantine].include?(mode)
      @mode = mode
      @findings = []
    end

    def run
      Identity.find_each do |identity|
        finding = assess(identity)
        next unless finding
        @findings << finding
        record_event(finding)
        apply_quarantine!(finding) if @mode == 'quarantine' && finding.risk == 'high'
      end
      @findings
    end

    def summary
      counts = @findings.group_by(&:risk).transform_values(&:count)
      { total: Identity.count, high: counts['high'].to_i,
        medium: counts['medium'].to_i, low: counts['low'].to_i, mode: @mode }
    end

    private

    def assess(identity)
      user = identity.user
      same_email = user.email.present? &&
                   user.email.casecmp(identity.provider_email.to_s).zero?
      reason = nil
      risk = nil

      if !identity.verified_email?
        if same_email
          risk = 'high'
          reason = "平台 #{identity.provider} 邮箱验证状态为 #{identity.email_verification}，" \
                   "却按同邮箱自动合并进了站内账号；可能是账号接管"
        else
          risk = 'medium'
          reason = '平台邮箱未验证且与站内邮箱不一致，无法证明身份归属'
        end
      elsif user.identities.active.count == 1 && user.password_digest.blank?
        risk = 'medium'
        reason = '平台邮箱虽已验证，但账号无密码且只有这一条登录凭据，建议人工复核'
      else
        risk = 'low'
        reason = '平台邮箱已验证，且账号有独立凭据'
      end

      Finding.new(identity: identity, risk: risk, reason: reason)
    end

    def record_event(finding)
      SecurityEvent.log!(
        'legacy_audit_finding',
        user: finding.identity.user, identity: finding.identity,
        provider: finding.identity.provider,
        detail: "#{finding.risk}: #{finding.reason} (mode=#{@mode})"
      )
    end

    def apply_quarantine!(finding)
      identity = finding.identity
      return if identity.status == 'quarantined'
      Identity.transaction do
        identity.quarantine!("legacy-audit: #{finding.reason}")
        SecurityEvent.log!('identity_quarantined', user: identity.user,
                           identity: identity, provider: identity.provider,
                           detail: finding.reason)
        MergeRequest.find_or_create_by!(
          provider: identity.provider, provider_uid: identity.provider_uid,
          target_user_id: identity.user_id, status: 'pending'
        ) do |mr|
          mr.provider_email = identity.provider_email
          mr.email_verification = identity.email_verification
        end
      end
    end
  end
end
