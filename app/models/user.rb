class User < ApplicationRecord
  has_secure_password validations: false
  has_many :identities, dependent: :destroy
  has_many :merge_requests, foreign_key: :target_user_id, dependent: :destroy

  EMAIL_FORMAT = /\A[^@\s]+@[^@\s]+\.[^@\s]+\z/.freeze

  validates :email, presence: true, uniqueness: { case_sensitive: false },
                    format: { with: EMAIL_FORMAT }
  before_save :normalize_email

  def self.find_by_normalized_email(email)
    find_by('lower(email) = ?', email.to_s.strip.downcase)
  end

  def verified?
    !!email_verified
  end

  # 还有其他可用凭据（密码或别的 active identity）时才允许解绑
  def can_remove_identity?(identity)
    password_digest.present? || identities.active.where.not(id: identity.id).exists?
  end

  private

  def normalize_email
    self.email = email.to_s.strip.downcase
  end
end
