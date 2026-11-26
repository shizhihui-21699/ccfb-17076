# frozen_string_literal: true

require "minitest/autorun"
require_relative "../lib/oauth_login"

# In-memory database rebuilt per test; tables are recreated in setup so test
# ordering never matters.
module TestDB
  def self.included(base)
    base.class_eval do
      @@connected = false # rubocop:disable Style/ClassVars
    end
  end

  def setup
    unless @@connected
      OAuthLogin::Database.connect!(":memory:")
      @@connected = true
    end
    OAuthLogin::Database.reset!
    @mailer = OAuthLogin::Mailer::LogMailer.new
  end

  def create_user!(email, verified: true)
    OAuthLogin::User.create!(email: email, email_verified: verified)
  end

  def login(auth_info_or_provider, payload = nil, mailer: @mailer)
    if auth_info_or_provider.is_a?(OAuthLogin::AuthInfo)
      OAuthLogin::Services::LoginService.new(mailer: mailer).call(auth_info_or_provider)
    else
      OAuthLogin.login(auth_info_or_provider, payload, mailer: mailer)
    end
  end

  def auth_info(provider:, uid:, email: nil, status: :not_requested)
    OAuthLogin::AuthInfo.new(provider: provider, uid: uid,
                             email: email, email_status: status)
  end
end
