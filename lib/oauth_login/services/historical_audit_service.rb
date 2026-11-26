# frozen_string_literal: true

require_relative "../provider_registry"
require_relative "../models/user"
require_relative "../models/oauth_identity"
require_relative "../models/audit_event"

module OAuthLogin
  module Services
    # Reconstructs and risk-grades every OAuth identity established before the
    # security redesign. The old code merged on bare email match, so any legacy
    # row whose provider cannot prove the email was verified must be treated as
    # a potential account takeover until the holder re-confirms.
    #
    # Severity:
    #   critical - legacy link via a provider that exposes NO email
    #              verification signal (facebook/twitter/microsoft-without-
    #              claim/wechat-style), OR a row recorded as unverified.
    #   high     - legacy link via a capable provider but with no stored
    #              verification snapshot (legacy_unknown / null status), so we
    #              cannot prove the email was verified at link time.
    #   info     - link_method "confirmed"/"signup" created after the fix, or a
    #              legacy row with a stored verified snapshot from a trusted
    #              provider (still listed for completeness, not quarantined).
    class HistoricalAuditService
      Finding = Struct.new(:identity, :severity, :reason, keyword_init: true)

      SEVERITIES = %w[critical high info].freeze

      # Providers whose email can never be treated as self-verified.
      UNTRUSTED_PROVIDERS = ProviderRegistry::PROFILES
                            .reject { |_, p| p[:trusts_verified_email] }
                            .keys.freeze

      def initialize(now: Time.now.utc)
        @now = now
      end

      # @param scope [ActiveRecord::Relation] override for partial scans
      # @return [Array<Finding>] sorted most severe first
      def audit(scope: OAuthIdentity.all)
        scope.includes(:user).find_each.map { |identity| grade(identity) }.compact
             .sort_by { |f| SEVERITIES.index(f.severity) }
      end

      # Apply quarantine to the risky rows. Defaults to a dry run so the tool
      # is safe to point at production; pass apply: true to write.
      def remediate(findings, apply: false, dry_run: !apply)
        actionable = findings.select { |f| %w[critical high].include?(f.severity) }
        actionable.each do |finding|
          if dry_run
            AuditEvent.new # no-op; callers render the plan themselves
            next
          end
          finding.identity.update!(
            quarantined: true,
            quarantine_reason: "historical audit: #{finding.severity} - #{finding.reason}"
          )
          AuditEvent.log!("identity_quarantined",
                          provider: finding.identity.provider,
                          uid: finding.identity.uid,
                          user: finding.identity.user,
                          email: finding.identity.email_at_link,
                          email_status: finding.identity.email_status_at_link,
                          detail: finding.reason)
        end
        actionable
      end

      private

      def grade(identity)
        return post_fix_finding(identity) unless identity.legacy?

        if unverified_snapshot?(identity) || UNTRUSTED_PROVIDERS.include?(identity.provider)
          Finding.new(identity: identity, severity: "critical",
                      reason: critical_reason(identity))
        elsif identity.email_status_at_link.nil? || identity.email_status_at_link.empty?
          Finding.new(identity: identity, severity: "high",
                      reason: "legacy link with no email-verification snapshot; cannot prove mailbox control")
        elsif identity.email_status_at_link == "verified"
          Finding.new(identity: identity, severity: "info",
                      reason: "legacy link but stored snapshot shows a provider-verified email")
        else
          Finding.new(identity: identity, severity: "high",
                      reason: "legacy link with unrecognized status #{identity.email_status_at_link.inspect}")
        end
      end

      def post_fix_finding(identity)
        Finding.new(identity: identity, severity: "info",
                    reason: "link_method=#{identity.link_method}; created under the confirmed-link policy")
      end

      def unverified_snapshot?(identity)
        %w[unverified not_provided not_requested].include?(identity.email_status_at_link)
      end

      def critical_reason(identity)
        if unverified_snapshot?(identity)
          "provider email was recorded as #{identity.email_status_at_link} yet the account was auto-merged"
        else
          "provider #{identity.provider} exposes no trustworthy email verification; auto-merge was unsafe"
        end
      end
    end
  end
end
