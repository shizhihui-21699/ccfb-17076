# frozen_string_literal: true

require "securerandom"
require "digest"

module OAuthLogin
  # A pending request to attach a provider identity to an EXISTING user.
  #
  # The request is created during an OAuth callback when the provider's email
  # matches an in-site account (or, for authenticated "connect this provider"
  # actions, when the logged-in user asks for a link). No session for the
  # target account is ever created from the OAuth callback itself: the caller
  # only receives an opaque, single-use, expiring token delivered out of band.
  class AccountLinkRequest < ActiveRecord::Base
    self.table_name = "account_link_requests"

    belongs_to :user

    VALID_STATES = %w[pending confirmed declined expired].freeze
    VALID_CONFIRMATIONS = %w[email_token login_token both].freeze

    validates :provider, :uid, :email_status, :required_confirmation,
              :state, :expires_at, presence: true
    validates :state, inclusion: { in: VALID_STATES }
    validates :required_confirmation, inclusion: { in: VALID_CONFIRMATIONS }

    scope :pending, -> { where(state: "pending") }

    class << self
      # Issue a fresh request. The raw token is returned ONCE alongside the
      # record; only its SHA-256 digest is stored, so a database leak cannot
      # be replayed.
      def issue!(user:, provider:, uid:, email:, email_status:,
                 required_confirmation:, ttl_seconds: 1800)
        raw_token = SecureRandom.urlsafe_base64(32)
        create!(
          user: user,
          provider: provider,
          uid: uid,
          email: email,
          email_status: email_status.to_s,
          required_confirmation: required_confirmation,
          state: "pending",
          token_digest: digest(raw_token),
          expires_at: Time.now.utc + ttl_seconds.to_i
        ).then { |record| [record, raw_token] }
      end

      def digest(raw_token)
        Digest::SHA256.hexdigest(raw_token.to_s)
      end
    end

    def needs_email_confirmation?
      %w[email_token both].include?(required_confirmation)
    end

    def needs_login_confirmation?
      %w[login_token both].include?(required_confirmation)
    end

    def decline!(reason)
      update!(state: "declined", decline_reason: reason.to_s)
    end

    def expire!
      update!(state: "expired") if state == "pending"
    end
  end
end
