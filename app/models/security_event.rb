class SecurityEvent < ApplicationRecord
  belongs_to :user, optional: true
  belongs_to :identity, optional: true
  belongs_to :merge_request, optional: true

  EVENTS = %w[
    oauth_login_success
    oauth_login_blocked_quarantined
    oauth_unknown_identity
    merge_request_created
    merge_request_confirmed
    merge_request_rejected
    identity_linked
    identity_unlinked
    identity_quarantined
    identity_restored
    legacy_audit_finding
    login_failed
  ].freeze

  validates :event_type, inclusion: { in: EVENTS }

  def self.log!(event_type, **attrs)
    raise ArgumentError, "unknown event #{event_type}" unless EVENTS.include?(event_type)
    create!(event_type: event_type, **attrs)
  end
end
