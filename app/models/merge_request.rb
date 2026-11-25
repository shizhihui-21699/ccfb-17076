class MergeRequest < ApplicationRecord
  belongs_to :target_user, class_name: 'User'
  has_many :security_events

  STATUSES = %w[pending confirmed rejected dismissed].freeze
  VERIFICATION_STATES = Identity::VERIFICATION_STATES

  validates :status, inclusion: { in: STATUSES }
  validates :email_verification, inclusion: { in: VERIFICATION_STATES }
  validates :provider, :provider_uid, presence: true

  scope :pending, -> { where(status: 'pending') }

  # 同一外部身份对同一账号只保留一个 pending 请求，避免通知轰炸
  def self.open_for(provider:, provider_uid:, target_user_id:)
    pending.find_by(provider: provider, provider_uid: provider_uid,
                    target_user_id: target_user_id)
  end

  def provider_email_verified?
    email_verification == 'verified'
  end

  # 签名 token：只对 pending 请求有效，过期由 TTL 控制。
  # Rails 6.0 的 MessageVerifier 不支持 purpose 关键字，把 purpose 放进 payload 自校验。
  TOKEN_PURPOSE = 'merge_request'

  def signed_id
    self.class.verifier.generate(
      { id: id, purpose: TOKEN_PURPOSE,
        expires_at: Rails.configuration.x.merge_token_ttl.from_now.to_i },
      expires_in: Rails.configuration.x.merge_token_ttl
    )
  end

  def self.verified_by_signed_id(token)
    payload = verifier.verify(token.to_s)
    return nil unless payload.is_a?(Hash) && payload[:purpose] == TOKEN_PURPOSE
    return nil if payload[:expires_at] && payload[:expires_at] < Time.current.to_i
    request = find(payload[:id])
    request.status == 'pending' ? request : nil
  rescue ActiveSupport::MessageVerifier::InvalidSignature, ActiveRecord::RecordNotFound
    nil
  end

  def self.verifier
    Rails.application.message_verifier(:merge_request)
  end

  def confirm!(note: nil)
    transaction do
      update!(status: 'confirmed', confirmed_at: Time.current, decision_note: note)
      identity = Identity.find_or_initialize_by(provider: provider, provider_uid: provider_uid) do |ident|
        ident.user = target_user
      end
      identity.user = target_user
      identity.provider_email = provider_email
      identity.email_verification = email_verification
      identity.status = 'active'
      identity.quarantine_reason = nil
      identity.linked_at = Time.current
      identity.save!
    end
  end

  def reject!(note: nil)
    update!(status: 'rejected', rejected_at: Time.current, decision_note: note)
  end
end
