# frozen_string_literal: true

require_relative "../auth_info"
require_relative "../provider_registry"
require_relative "../models/user"
require_relative "../models/oauth_identity"
require_relative "../models/account_link_request"
require_relative "../models/audit_event"

module OAuthLogin
  # Raised when an OAuth (provider, uid) is already bound to a different local
  # user than the one a callback is trying to reach. Never auto-reattach.
  class IdentityConflict < StandardError; end

  module Services
    # Result of processing an OAuth callback.
    #
    # +outcome+ is one of:
    #   :session_created        - identity known and healthy; safe to log in
    #   :signup_pending         - brand new user, provider email not trusted;
    #                             account exists but is NOT usable until our
    #                             own verification mail is clicked
    #   :signup_ready           - brand new user from a high-trust provider
    #                             with a verified email; session may start
    #   :merge_requested        - email collides with an existing account;
    #                             NOTHING is linked and no session is created.
    #                             A confirmation request was issued.
    #   :quarantined            - the identity exists but was distrusted by
    #                             the historical audit
    #   :identity_conflict      - provider uid is attached to another user
    #                             (account-takeover attempt shape)
    class LoginResult
      attr_reader :outcome, :user, :identity, :link_request, :raw_token, :reason

      def initialize(outcome:, user: nil, identity: nil, link_request: nil,
                     raw_token: nil, reason: nil)
        @outcome = outcome
        @user = user
        @identity = identity
        @link_request = link_request
        @raw_token = raw_token
        @reason = reason
        freeze
      end

      def session?
        outcome == :session_created || outcome == :signup_ready
      end
    end

    # The single entry point used by every provider's OAuth callback.
    #
    # Security invariants enforced here (each has a test):
    #   1. A known, healthy identity logs in its own user only.
    #   2. A quarantined identity never logs in.
    #   3. An email match with an existing user NEVER creates a session or a
    #      link. It always creates an AccountLinkRequest requiring the holder.
    #   4. The required confirmation strength depends on whether the provider
    #      verified the email.
    #   5. A provider uid already linked to a different user is a hard block.
    #   6. Providers without emails can never match into an existing account.
    class LoginService
      TTL_SECONDS = 1800

      def initialize(mailer: nil)
        @mailer = mailer
      end

      # @param auth_info [AuthInfo] normalized provider payload
      # @return [LoginResult]
      def call(auth_info)
        unless auth_info.is_a?(AuthInfo)
          raise ArgumentError, "expected an AuthInfo, got #{auth_info.class}"
        end
        unless ProviderRegistry.supported?(auth_info.provider)
          raise ProviderRegistry::UnknownProvider, auth_info.provider
        end

        AuditEvent.log!("oauth_login_started",
                        provider: auth_info.provider, uid: auth_info.uid,
                        email: auth_info.email, email_status: auth_info.email_status)

        handle_known_identity(auth_info) || handle_new_identity(auth_info)
      end

      private

      def handle_known_identity(auth_info)
        identity = OAuthIdentity.find_by(provider: auth_info.provider, uid: auth_info.uid)
        return nil unless identity

        AuditEvent.log!("oauth_login_identity_found",
                        provider: auth_info.provider, uid: auth_info.uid,
                        user: identity.user, email: auth_info.email,
                        email_status: auth_info.email_status)

        # Takeover-shape guard: a (provider, uid) already bound to user A must
        # never resolve into user B even if the callback now carries B's email.
        if auth_info.email?
          email_owner = User.find_by("lower(email) = ?", auth_info.email)
          if email_owner && email_owner.id != identity.user_id
            AuditEvent.log!("oauth_login_blocked_identity_conflict",
                            provider: auth_info.provider, uid: auth_info.uid,
                            user: identity.user, email: auth_info.email,
                            detail: "uid belongs to #{identity.user_id} but email " \
                                    "belongs to #{email_owner.id}")
            raise OAuthLogin::IdentityConflict,
                  "provider identity is linked to a different account than the email owner"
          end
        end

        if identity.quarantined?
          AuditEvent.log!("oauth_login_blocked_quarantined",
                          provider: auth_info.provider, uid: auth_info.uid,
                          user: identity.user, email: auth_info.email,
                          detail: identity.quarantine_reason)
          return LoginResult.new(outcome: :quarantined, identity: identity,
                                 user: identity.user,
                                 reason: identity.quarantine_reason)
        end

        LoginResult.new(outcome: :session_created, identity: identity,
                        user: identity.user)
      end

      def handle_new_identity(auth_info)
        existing = auth_info.email? &&
                   User.find_by("lower(email) = ?", auth_info.email)

        if existing
          request_merge(existing, auth_info)
        else
          register_new_user(auth_info)
        end
      end

      # The heart of the fix: email collision -> confirmation request only.
      def request_merge(user, auth_info)
        ensure_no_other_identity!(user, auth_info)

        required = decide_confirmation(auth_info)
        link_request, raw_token = AccountLinkRequest.issue!(
          user: user,
          provider: auth_info.provider,
          uid: auth_info.uid,
          email: auth_info.email,
          email_status: auth_info.email_status,
          required_confirmation: required,
          ttl_seconds: TTL_SECONDS
        )

        AuditEvent.log!("oauth_login_merge_requested",
                        provider: auth_info.provider, uid: auth_info.uid,
                        user: user, email: auth_info.email,
                        email_status: auth_info.email_status,
                        detail: "required=#{required} request_id=#{link_request.id}")

        deliver_merge_mail(user, auth_info, link_request, raw_token)

        LoginResult.new(outcome: :merge_requested, user: user,
                        link_request: link_request, raw_token: raw_token,
                        reason: "email matches existing account; holder confirmation required")
      end

      # Even before issuing a request, refuse the takeover shape where the
      # same (provider, uid) is somehow already bound elsewhere. The unique
      # index is the backstop; this gives a clean, audited error.
      def ensure_no_other_identity!(user, auth_info)
        other = OAuthIdentity.where(provider: auth_info.provider, uid: auth_info.uid)
                             .where.not(user_id: user.id).first
        return unless other

        AuditEvent.log!("oauth_login_blocked_identity_conflict",
                        provider: auth_info.provider, uid: auth_info.uid,
                        user: other.user, email: auth_info.email,
                        detail: "request targeted user #{user.id} but uid belongs to #{other.user_id}")
        raise OAuthLogin::IdentityConflict,
              "provider identity already linked to another account"
      end

      # Confirmation strength:
      #   verified email from a provider we trust -> holder must still approve
      #     via the existing account (login_token).
      #   anything else (unverified / no signal / no email) -> prove BOTH the
      #     mailbox (email_token) and the existing account (login_token).
      def decide_confirmation(auth_info)
        if auth_info.email_verified? &&
           ProviderRegistry.trusts_verified_email?(auth_info.provider)
          "login_token"
        else
          "both"
        end
      end

      def register_new_user(auth_info)
        trusted = auth_info.email_verified? &&
                  ProviderRegistry.trusts_verified_email?(auth_info.provider)

        user = User.create!(
          email: auth_info.email || "pending-#{auth_info.provider}-#{auth_info.uid}@placeholder.local",
          email_verified: trusted,
          display_name: auth_info.metadata["name"]
        )

        if trusted
          identity = link_identity!(user, auth_info, method: "signup")
          AuditEvent.log!("oauth_login_new_user", provider: auth_info.provider,
                          uid: auth_info.uid, user: user, email: user.email,
                          email_status: auth_info.email_status)
          return LoginResult.new(outcome: :signup_ready, user: user, identity: identity)
        end

        # Unverified/new signal: create the user shell and a link request but
        # leave them unable to start a session until our own mail is confirmed.
        required = auth_info.email? ? "email_token" : "login_token"
        link_request, raw_token = AccountLinkRequest.issue!(
          user: user, provider: auth_info.provider, uid: auth_info.uid,
          email: auth_info.email, email_status: auth_info.email_status,
          required_confirmation: required, ttl_seconds: TTL_SECONDS
        )
        AuditEvent.log!("oauth_login_email_unverified_pending",
                        provider: auth_info.provider, uid: auth_info.uid,
                        user: user, email: auth_info.email,
                        email_status: auth_info.email_status,
                        detail: "request_id=#{link_request.id}")
        deliver_verification_mail(user, auth_info, link_request, raw_token)

        LoginResult.new(outcome: :signup_pending, user: user,
                        link_request: link_request, raw_token: raw_token)
      end

      def link_identity!(user, auth_info, method:)
        OAuthIdentity.create!(
          user: user,
          provider: auth_info.provider,
          uid: auth_info.uid,
          email_at_link: auth_info.email,
          email_status_at_link: auth_info.email_status.to_s,
          provider_email_verified: auth_info.email_verified?,
          link_method: method
        ).tap do |identity|
          AuditEvent.log!("identity_linked", provider: auth_info.provider,
                          uid: auth_info.uid, user: user, email: auth_info.email,
                          email_status: auth_info.email_status,
                          detail: "method=#{method} identity_id=#{identity.id}")
        end
      end

      def deliver_merge_mail(user, auth_info, request, raw_token)
        return unless @mailer
        @mailer.merge_confirmation(
          user: user, auth_info: auth_info, link_request: request,
          token: raw_token
        )
      end

      def deliver_verification_mail(user, auth_info, request, raw_token)
        return unless @mailer
        @mailer.signup_verification(
          user: user, auth_info: auth_info, link_request: request,
          token: raw_token
        )
      end
    end
  end
end
