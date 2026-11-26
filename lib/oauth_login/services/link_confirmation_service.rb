# frozen_string_literal: true

require_relative "../models/user"
require_relative "../models/oauth_identity"
require_relative "../models/account_link_request"
require_relative "../models/audit_event"

module OAuthLogin
  module Services
    # Processes a holder's confirmation of a pending AccountLinkRequest.
    #
    # Confirmation legs, mirroring +required_confirmation+:
    #
    #   email_token  - presenting the raw token (delivered out-of-band by email
    #                  to the contested address) proves control of that mailbox.
    #   login_token  - approving while authenticated as the TARGET user proves
    #                  control of the existing in-site account.
    #
    # A "both" request needs BOTH legs. The raw token stays valid for the
    # request's lifetime rather than being consumed on the first leg, because a
    # holder may click the mail link while already logged in (satisfying both
    # legs in one request) or while logged out (email leg first, login later).
    # Single-use semantics are enforced by state: once no longer +pending+, the
    # request is inert.
    class LinkConfirmationService
      ConfirmationError = Class.new(StandardError)
      class InvalidToken < ConfirmationError; end
      class WrongUser < ConfirmationError; end
      class RequestExpired < ConfirmationError; end

      # Email leg. Validates the token and marks mailbox control proven.
      #
      # @return [AccountLinkRequest] the updated request (still pending unless
      #   no login leg is required, in which case it is finalized)
      def confirm_by_email(raw_token)
        request = find_by_token(raw_token)
        raise WrongUser, "request does not require email confirmation" unless
          request.needs_email_confirmation?

        request.update!(email_proven: true)
        AuditEvent.log!("link_request_confirmed",
                        provider: request.provider, uid: request.uid,
                        user: request.user, email: request.email,
                        detail: "leg=email request_id=#{request.id}")

        finalize_if_complete(request)
      end

      # Login leg (also the only leg for login_token-only requests).
      #
      # @param request_id [Integer]
      # @param current_user [User] the authenticated holder; MUST be the target
      # @param raw_token [String, nil] required when the email leg has not yet
      #   been recorded, so a single in-session click can satisfy both legs
      # @return [OAuthIdentity] the newly linked identity
      def confirm_in_session(request_id:, current_user:, raw_token: nil)
        request = AccountLinkRequest.pending.find_by(id: request_id)
        raise InvalidToken, "request not found or no longer pending" unless request
        raise WrongUser, "cannot confirm a link for another account" unless
          request.user_id == current_user.id
        raise RequestExpired, "request expired" if request.expires_at < Time.now.utc

        if request.needs_email_confirmation?
          if !request.email_proven?
            raise InvalidToken, "email control must be proven first" unless
              valid_token?(request, raw_token)
            request.update!(email_proven: true)
            AuditEvent.log!("link_request_confirmed",
                            provider: request.provider, uid: request.uid,
                            user: request.user, email: request.email,
                            detail: "leg=email(in-session) request_id=#{request.id}")
          end
        end

        request.update!(login_proven: true)
        AuditEvent.log!("link_request_confirmed",
                        provider: request.provider, uid: request.uid,
                        user: request.user, email: request.email,
                        detail: "leg=login request_id=#{request.id}")

        finalize_if_complete(request)
      end

      def decline(request_id:, current_user:, reason: "declined by account holder")
        request = AccountLinkRequest.find(request_id)
        raise WrongUser, "cannot decline a link for another account" unless
          request.user_id == current_user.id

        request.decline!(reason)
        AuditEvent.log!("link_request_declined",
                        provider: request.provider, uid: request.uid,
                        user: current_user, email: request.email,
                        detail: reason)
        request
      end

      private

      def find_by_token(raw_token)
        request = AccountLinkRequest.pending.find_by(
          token_digest: AccountLinkRequest.digest(raw_token)
        )
        raise InvalidToken, "unknown or stale token" unless request
        raise RequestExpired, "token expired" if request.expires_at < Time.now.utc

        request
      end

      def valid_token?(request, raw_token)
        return false if raw_token.nil? || raw_token.to_s.empty?
        secure_compare(request.token_digest,
                       AccountLinkRequest.digest(raw_token))
      end

      # Constant-time compare; ActiveSupport provides this but we avoid leaning
      # on framework load order.
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize
        l = a.unpack("C*")
        r = 0
        b.each_byte { |byte| r |= byte ^ l.shift }
        r.zero?
      end

      def finalize_if_complete(request)
        required_email = !request.needs_email_confirmation? || request.email_proven?
        required_login = !request.needs_login_confirmation? || request.login_proven?

        # Multi-leg requests stay pending until every leg is satisfied.
        return request unless required_email && required_login

        identity = nil
        AccountLinkRequest.transaction do
          request.lock!
          raise InvalidToken, "request already handled" unless request.state == "pending"

          identity = OAuthIdentity.create!(
            user_id: request.user_id,
            provider: request.provider,
            uid: request.uid,
            email_at_link: request.email,
            email_status_at_link: request.email_status,
            provider_email_verified: request.email_status == "verified",
            link_method: "confirmed"
          )
          request.update!(state: "confirmed", confirmed_at: Time.now.utc,
                          confirmed_by_user_id: request.user_id)
        end

        AuditEvent.log!("identity_linked",
                        provider: request.provider, uid: request.uid,
                        user: request.user, email: request.email,
                        email_status: request.email_status,
                        detail: "method=confirmed request_id=#{request.id} identity_id=#{identity.id}")
        identity
      end
    end
  end
end
