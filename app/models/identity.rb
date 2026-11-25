class Identity < ApplicationRecord
  belongs_to :user
  has_many :security_events

  STATUSES = %w[active quarantined].freeze
  VERIFICATION_STATES = %w[verified unverified unknown].freeze

  validates :provider, :provider_uid, presence: true
  validates :status, inclusion: { in: STATUSES }
  validates :email_verification, inclusion: { in: VERIFICATION_STATES }
  validates :provider_uid, uniqueness: { scope: :provider }

  scope :active, -> { where(status: 'active') }
  scope :quarantined, -> { where(status: 'quarantined') }

  def verified_email?
    email_verification == 'verified'
  end

  def quarantine!(reason)
    update!(status: 'quarantined', quarantine_reason: reason)
  end

  def restore!
    update!(status: 'active', quarantine_reason: nil)
  end
end
