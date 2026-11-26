# frozen_string_literal: true

require_relative "test_helper"

class AdaptersTest < Minitest::Test
  include TestDB

  def test_google_boolean_true_is_verified
    info = OAuthLogin::Services::ProviderExchange.parse(
      "google",
      "sub" => "g1", "email" => "a@example.com", "email_verified" => true
    )
    assert_equal :verified, info.email_status
    assert info.email_verified?
  end

  def test_google_string_true_is_also_verified
    info = OAuthLogin::Services::ProviderExchange.parse(
      "google",
      "sub" => "g2", "email" => "a@example.com", "email_verified" => "true"
    )
    assert_equal :verified, info.email_status
  end

  def test_google_explicit_false_is_unverified_never_verified
    info = OAuthLogin::Services::ProviderExchange.parse(
      "google",
      "sub" => "g3", "email" => "a@example.com", "email_verified" => false
    )
    assert_equal :unverified, info.email_status
    refute info.email_verified?
  end

  def test_google_missing_claim_is_not_provided
    info = OAuthLogin::Services::ProviderExchange.parse(
      "google", "sub" => "g4", "email" => "a@example.com"
    )
    assert_equal :not_provided, info.email_status
  end

  def test_apple_string_claims_and_relay_flag
    info = OAuthLogin::Services::ProviderExchange.parse(
      "apple",
      "sub" => "001.abc", "email" => "priv@privaterelay.appleid.com",
      "email_verified" => "true", "is_private_email" => "true"
    )
    assert_equal :verified, info.email_status
    assert_equal true, info.metadata["private_email"]
  end

  def test_apple_returning_user_has_no_email_claim
    info = OAuthLogin::Services::ProviderExchange.parse("apple", "sub" => "001.abc")
    assert_equal :not_requested, info.email_status
    refute info.email?
  end

  def test_github_requires_emails_endpoint_for_verification
    info = OAuthLogin::Services::ProviderExchange.parse(
      "github",
      "user" => { "id" => 99, "email" => "dev@example.com" },
      "emails" => [
        { "email" => "dev@example.com", "verified" => true, "primary" => true }
      ]
    )
    assert_equal :verified, info.email_status
  end

  def test_github_unverified_entry_stays_unverified
    info = OAuthLogin::Services::ProviderExchange.parse(
      "github",
      "user" => { "id" => 99 },
      "emails" => [
        { "email" => "dev@example.com", "verified" => false, "primary" => true }
      ]
    )
    assert_equal :unverified, info.email_status
  end

  def test_github_without_emails_list_never_trusts_user_email
    info = OAuthLogin::Services::ProviderExchange.parse(
      "github", "user" => { "id" => 99, "email" => "dev@example.com" }
    )
    assert_equal :not_requested, info.email_status
    assert_nil info.email
  end

  def test_microsoft_truthy_claim_verified
    info = OAuthLogin::Services::ProviderExchange.parse(
      "microsoft",
      "sub" => "m1", "email" => "x@corp.com", "email_verified" => "true"
    )
    assert_equal :verified, info.email_status
  end

  def test_microsoft_upn_without_claim_is_not_provided
    info = OAuthLogin::Services::ProviderExchange.parse(
      "microsoft", "sub" => "m2", "upn" => "guest@partner.com"
    )
    assert_equal :not_provided, info.email_status
    refute info.email_verified?
  end

  def test_microsoft_preferred_username_alone_is_not_proof
    info = OAuthLogin::Services::ProviderExchange.parse(
      "microsoft", "sub" => "m3", "preferred_username" => "m3@example.com"
    )
    assert_equal :not_provided, info.email_status
  end

  def test_facebook_never_verified_even_with_email
    info = OAuthLogin::Services::ProviderExchange.parse(
      "facebook", "id" => "fb1", "email" => "victim@example.com"
    )
    assert_equal :not_provided, info.email_status
    refute info.email_verified?
  end

  def test_twitter_never_verified
    info = OAuthLogin::Services::ProviderExchange.parse(
      "twitter", "id" => "tw1", "email" => "victim@example.com"
    )
    assert_equal :not_provided, info.email_status
  end

  def test_wechat_has_no_email_at_all
    info = OAuthLogin::Services::ProviderExchange.parse(
      "wechat", "openid" => "wx1", "unionid" => "un1"
    )
    assert_equal :not_requested, info.email_status
    refute info.email?
  end

  def test_unknown_provider_raises
    assert_raises(OAuthLogin::ProviderRegistry::UnknownProvider) do
      OAuthLogin::Services::ProviderExchange.parse("myspace", {})
    end
  end

  def test_email_is_downcased_and_stripped
    info = OAuthLogin::AuthInfo.new(provider: "google", uid: "x",
                                   email: "  A@B.COM ", email_status: :verified)
    assert_equal "a@b.com", info.email
  end

  def test_auth_info_rejects_unknown_status
    assert_raises(ArgumentError) do
      OAuthLogin::AuthInfo.new(provider: "google", uid: "x", email_status: :maybe)
    end
  end
end
