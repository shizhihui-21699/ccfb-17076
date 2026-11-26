# frozen_string_literal: true

require_relative "test_helper"

class HistoricalAuditServiceTest < Minitest::Test
  include TestDB

  def setup
    super
    @victim = create_user!("victim@example.com")
    @alice = create_user!("alice@example.com")
    @service = OAuthLogin::Services::HistoricalAuditService.new
  end

  def test_facebook_auto_merge_is_critical
    identity = legacy_identity(@victim, "facebook", "fb-1", nil)
    finding = find_finding(identity)
    assert_equal "critical", finding.severity
  end

  def test_recorded_unverified_snapshot_is_critical_even_on_trusted_provider
    identity = legacy_identity(@victim, "google", "g-1", "unverified")
    finding = find_finding(identity)
    assert_equal "critical", finding.severity
  end

  def test_legacy_google_without_snapshot_is_high
    identity = legacy_identity(@victim, "google", "g-2", nil,
                               method: "legacy_unknown")
    finding = find_finding(identity)
    assert_equal "high", finding.severity
  end

  def test_legacy_verified_snapshot_is_info
    identity = legacy_identity(@alice, "google", "g-3", "verified",
                               verified: true)
    finding = find_finding(identity)
    assert_equal "info", finding.severity
  end

  def test_post_fix_confirmed_link_is_info
    identity = OAuthLogin::OAuthIdentity.create!(
      user: @alice, provider: "google", uid: "g-ok",
      email_status_at_link: "verified", provider_email_verified: true,
      link_method: "confirmed"
    )
    assert_equal "info", find_finding(identity).severity
  end

  def test_dry_run_does_not_mutate
    identity = legacy_identity(@victim, "twitter", "tw-1", nil)
    findings = @service.audit
    @service.remediate(findings, dry_run: true)
    refute identity.reload.quarantined?
  end

  def test_apply_quarantines_critical_and_high_only
    bad = legacy_identity(@victim, "facebook", "fb-x", nil)
    medium = legacy_identity(@alice, "google", "g-m", nil,
                             method: "legacy_unknown")
    good = OAuthLogin::OAuthIdentity.create!(
      user: @alice, provider: "google", uid: "g-good",
      email_status_at_link: "verified", link_method: "confirmed",
      provider_email_verified: true
    )

    findings = @service.audit
    quarantined = @service.remediate(findings, apply: true)

    assert_equal 2, quarantined.size
    assert bad.reload.quarantined?
    assert medium.reload.quarantined?
    refute good.reload.quarantined?
    assert_includes OAuthLogin::AuditEvent.pluck(:event_type),
                    "identity_quarantined"
  end

  def test_quarantined_legacy_identity_blocks_later_login
    legacy_identity(@victim, "facebook", "fb-block", nil)
    findings = @service.audit
    @service.remediate(findings, apply: true)

    result = login("facebook",
                   "id" => "fb-block", "email" => "victim@example.com")
    assert_equal :quarantined, result.outcome
  end

  private

  def legacy_identity(user, provider, uid, status, method: "auto_email_match",
                      verified: false)
    OAuthLogin::OAuthIdentity.create!(
      user: user, provider: provider, uid: uid,
      email_at_link: user.email, email_status_at_link: status,
      provider_email_verified: verified, link_method: method
    )
  end

  def find_finding(identity)
    @service.audit.find { |f| f.identity.id == identity.id }
  end
end
