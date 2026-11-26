# frozen_string_literal: true

module OAuthLogin
  class User < ActiveRecord::Base
    self.table_name = "users"

    has_many :oauth_identities, dependent: :restrict_with_error
    has_many :account_link_requests, dependent: :destroy

    validates :email, presence: true, uniqueness: { case_sensitive: false }
    validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }

    before_validation { self.email = email.to_s.strip.downcase }

    def to_s
      "#<User id=#{id} email=#{email} verified=#{email_verified}>"
    end
  end
end
