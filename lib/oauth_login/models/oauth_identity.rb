# frozen_string_literal: true

module OAuthLogin
  class OAuthIdentity < ActiveRecord::Base
    self.table_name = "oauth_identities"

    belongs_to :user

    validates :provider, :uid, :link_method, presence: true
    validates :uid, uniqueness: { scope: :provider }
    validates :link_method,
              inclusion: { in: %w[signup confirmed auto_email_match legacy_unknown] }

    scope :active, -> { where(quarantined: false) }
    scope :quarantined, -> { where(quarantined: true) }

    # Legacy rows created before the security redesign carry no trustworthy
    # record of whether the provider email was verified.
    def legacy?
      %w[auto_email_match legacy_unknown].include?(link_method)
    end

    def usable_for_login?
      !quarantined?
    end

    def to_s
      "#<OAuthIdentity id=#{id} #{provider}:#{uid} user_id=#{user_id} " \
        "method=#{link_method} quarantined=#{quarantined}>"
    end
  end
end
