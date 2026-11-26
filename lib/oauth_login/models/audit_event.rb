# frozen_string_literal: true

module OAuthLogin
  # Append-only security audit trail. Nothing in the app updates or deletes
  # these rows; the historical-merge audit script reads them to reconstruct
  # what the old auto-merge code did.
  class AuditEvent < ActiveRecord::Base
    self.table_name = "audit_events"

    belongs_to :user, optional: true

    validates :event_type, presence: true

    EVENTS = %w[
      oauth_login_started
      oauth_login_identity_found
      oauth_login_new_user
      oauth_login_email_unverified_pending
      oauth_login_merge_requested
      oauth_login_blocked_quarantined
      oauth_login_blocked_identity_conflict
      link_request_confirmed
      link_request_declined
      link_request_expired
      identity_linked
      identity_quarantined
      identity_released
    ].freeze

    class << self
      def log!(event_type, provider: nil, uid: nil, user: nil, email: nil,
              email_status: nil, detail: nil)
        raise ArgumentError, "unknown event #{event_type}" unless EVENTS.include?(event_type)

        create!(
          event_type: event_type,
          provider: provider,
          uid: uid,
          user: user,
          email: email,
          email_status: email_status&.to_s,
          detail: detail
        )
      end
    end
  end
end
