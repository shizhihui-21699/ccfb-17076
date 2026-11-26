# frozen_string_literal: true

require_relative "test_helper"

# These tests encode the security guarantees of the redesign. Each test name is
# a property that must hold regardless of provider quirks.
class LoginServiceSecurityTest < Minitest::Test
  include TestDB

  # --- The original incident ---------------------------------------------

  def test_unverified_provider_email_collision_does_not_take_over_account
    victim = create_user!("victim@example.com")

    result = login(
      "facebook",
      "id" => "attacker-fb", "email" => "victim@example.com"
    )

    assert_equal :merge_requested, result.outcome
    assert_equal victim.id, result.user.id

    # No new identity attached to the victim.
    assert_empty OAuthLogin::OAuthIdentity.where(user_id: victim.id)
    # No session-worthy result, and the reason is explicit.
    refute result.session?

    request = result.link_request
    assert_equal "both", request.required_confirmation
    assert_equal "pending", request.state
    refute_nil result.raw_token
    # A confirmation mail went to the contested mailbox / account holder.
    assert_equal 1, @mailer.deliveries.size
    assert_equal "merge_confirmation", @mailer.deliveries.first[:kind]
  end

  def test_even_verified_provider_email_collision_requires_holder_confirmation
    victim = create_user!("victim@example.com")

    result = login(
      "google",
      "sub" => "g-new", "email" => "victim@example.com",
      "email_verified" => true
    )

    assert_equal :merge_requested, result.outcome
    assert_equal "login_token", result.link_request.required_confirmation
    assert_empty OAuthLogin::OAuthIdentity.where(user_id: victim.id)
    refute result.session?
  end

  def test_trusted_provider_with_unverified_email_collision_escalates_to_both
    victim = create_user!("victim@example.com")

    result = login(
      "google",
      "sub" => "g-unverif", "email" => "victim@example.com",
      "email_verified" => false
    )

    assert_equal :merge_requested, result.outcome
    assert_equal "both", result.link_request.required_confirmation
    assert_empty OAuthLogin::OAuthIdentity.where(user_id: victim.id)
  end

  def test_attacker_cannot_complete_merge_without_holding_the_account
    victim = create_user!("victim@example.com")
    result = login("facebook",
                   "id" => "attacker-fb", "email" => "victim@example.com")
    token = result.raw_token
    request = result.link_request

    # Attacker controls the fake mailbox, so they can pass the email leg...
    OAuthLogin::Services::LinkConfirmationService.new.confirm_by_email(token)
    request.reload
    assert request.email_proven?

    # ...but the login leg must run as the victim. Running it as a different
    # authenticated user is refused.
    attacker_site_user = create_user!("attacker@evil.com")
    assert_raises OAuthLogin::Services::LinkConfirmationService::WrongUser do
      OAuthLogin::Services::LinkConfirmationService.new.confirm_in_session(
        request_id: request.id, current_user: attacker_site_user
      )
    end

    # Email leg alone must NOT have created the identity.
    assert_empty OAuthLogin::OAuthIdentity.where(user_id: victim.id)
    request.reload
    assert_equal "pending", request.state
  end

  def test_full_legitimate_merge_succeeds_when_holder_completes_both_legs
    victim = create_user!("victim@example.com")
    result = login("facebook",
                   "id" => "fb-new", "email" => "victim@example.com")
    token = result.raw_token
    request = result.link_request

    service = OAuthLogin::Services::LinkConfirmationService.new
    service.confirm_by_email(token)
    identity = service.confirm_in_session(request_id: request.id,
                                          current_user: victim)

    assert_equal victim.id, identity.user_id
    assert_equal "confirmed", identity.link_method
    request.reload
    assert_equal "confirmed", request.state
    # Subsequent login with the same identity now works directly.
    second = login("facebook",
                   "id" => "fb-new", "email" => "victim@example.com")
    assert_equal :session_created, second.outcome
  end

  def test_holder_can_decline_and_identity_is_never_linked
    victim = create_user!("victim@example.com")
    result = login("facebook",
                   "id" => "fb-x", "email" => "victim@example.com")

    OAuthLogin::Services::LinkConfirmationService.new.decline(
      request_id: result.link_request.id, current_user: victim,
      reason: "I never use Facebook"
    )
    assert_empty OAuthLogin::OAuthIdentity.where(user_id: victim.id)
    result.link_request.reload
    assert_equal "declined", result.link_request.state
  end

  # --- Known identity handling -------------------------------------------

  def test_known_healthy_identity_logs_in
    user = create_user!("a@example.com")
    OAuthLogin::OAuthIdentity.create!(
      user: user, provider: "google", uid: "g-1",
      email_status_at_link: "verified", link_method: "signup"
    )

    result = login("google",
                   "sub" => "g-1", "email" => "a@example.com",
                   "email_verified" => true)
    assert_equal :session_created, result.outcome
    assert_equal user.id, result.user.id
  end

  def test_quarantined_identity_is_blocked
    user = create_user!("a@example.com")
    OAuthLogin::OAuthIdentity.create!(
      user: user, provider: "facebook", uid: "fb-old",
      link_method: "auto_email_match", quarantined: true,
      quarantine_reason: "historical audit: critical"
    )

    result = login("facebook", "id" => "fb-old", "email" => "a@example.com")
    assert_equal :quarantined, result.outcome
    refute result.session?
  end

  def test_provider_uid_bound_elsewhere_is_hard_conflict
    owner = create_user!("owner@example.com")
    OAuthLogin::OAuthIdentity.create!(
      user: owner, provider: "google", uid: "g-shared",
      link_method: "signup", email_status_at_link: "verified"
    )
    create_user!("collision@example.com")

    # A crafted callback whose uid is already owned but whose email matches a
    # different local user must raise rather than silently re-attach.
    assert_raises OAuthLogin::IdentityConflict do
      login("google",
            "sub" => "g-shared", "email" => "collision@example.com",
            "email_verified" => true)
    end
  end

  # --- New signups --------------------------------------------------------

  def test_new_user_from_trusted_verified_provider_gets_session
    result = login("google",
                   "sub" => "g-fresh", "email" => "fresh@example.com",
                   "email_verified" => true)
    assert_equal :signup_ready, result.outcome
    assert result.session?
    assert result.user.email_verified
    assert_equal "signup", result.identity.link_method
  end

  def test_new_user_from_untrusted_provider_is_pending_no_session
    result = login("facebook",
                   "id" => "fb-fresh", "email" => "fresh@example.com")
    assert_equal :signup_pending, result.outcome
    refute result.session?
    assert_nil OAuthLogin::OAuthIdentity.find_by(provider: "facebook",
                                                 uid: "fb-fresh")
    assert_equal "email_token", result.link_request.required_confirmation
  end

  def test_emailless_provider_cannot_match_into_existing_account
    create_user!("someone@example.com")
    result = login("wechat", "openid" => "wx-1", "unionid" => "un-1")
    # No email -> a pending shell user, never a merge with someone@example.com.
    assert_equal :signup_pending, result.outcome
    refute_equal "someone@example.com", result.user.email
  end

  # --- Token hygiene ------------------------------------------------------

  def test_token_digest_storage_is_not_reversible
    result = login("facebook",
                   "id" => "fb-t", "email" => "victim@example.com")
    request = result.link_request
    refute_equal result.raw_token, request.token_digest
    assert_match(/\A[0-9a-f]{64}\z/, request.token_digest)
  end

  def test_expired_request_cannot_be_confirmed
    victim = create_user!("victim@example.com")
    result = login("facebook",
                   "id" => "fb-e", "email" => "victim@example.com")
    result.link_request.update!(expires_at: Time.now.utc - 60)

    assert_raises OAuthLogin::Services::LinkConfirmationService::RequestExpired do
      OAuthLogin::Services::LinkConfirmationService.new
        .confirm_by_email(result.raw_token)
    end
  end

  def test_garbage_token_is_rejected
    create_user!("victim@example.com")
    assert_raises OAuthLogin::Services::LinkConfirmationService::InvalidToken do
      OAuthLogin::Services::LinkConfirmationService.new
        .confirm_by_email("not-a-real-token")
    end
  end

  def test_login_leg_requires_email_leg_first_for_both_request
    victim = create_user!("victim@example.com")
    result = login("facebook",
                   "id" => "fb-legs", "email" => "victim@example.com")
    assert_raises OAuthLogin::Services::LinkConfirmationService::InvalidToken do
      OAuthLogin::Services::LinkConfirmationService.new.confirm_in_session(
        request_id: result.link_request.id, current_user: victim
      )
    end
  end

  def test_in_session_click_with_valid_token_satisfies_both_legs_at_once
    victim = create_user!("victim@example.com")
    result = login("facebook",
                   "id" => "fb-once", "email" => "victim@example.com")
    identity = OAuthLogin::Services::LinkConfirmationService.new.confirm_in_session(
      request_id: result.link_request.id, current_user: victim,
      raw_token: result.raw_token
    )
    assert_equal victim.id, identity.user_id
  end

  def test_audit_trail_records_every_security_decision
    create_user!("victim@example.com")
    login("facebook", "id" => "fb-audit", "email" => "victim@example.com")

    events = OAuthLogin::AuditEvent.pluck(:event_type)
    assert_includes events, "oauth_login_started"
    assert_includes events, "oauth_login_merge_requested"
    refute_includes events, "identity_linked"
  end
end
