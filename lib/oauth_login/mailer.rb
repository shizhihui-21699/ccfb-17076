# frozen_string_literal: true

require "logger"

module OAuthLogin
  # Mailer boundary. Real deployments implement the same two methods against
  # ActionMailer / a transactional provider; tests and local dev use
  # LogMailer, which captures messages in memory and writes them to a logger so
  # the full token flow can be exercised without SMTP.
  module Mailer
    class LogMailer
      attr_reader :deliveries

      def initialize(logger: Logger.new(IO::NULL))
        @logger = logger
        @deliveries = []
      end

      def merge_confirmation(user:, auth_info:, link_request:, token:)
        record(
          to: user.email,
          kind: "merge_confirmation",
          subject: "Confirm linking #{auth_info.provider.capitalize} to your account",
          body: merge_body(user, auth_info, link_request, token)
        )
      end

      def signup_verification(user:, auth_info:, link_request:, token:)
        record(
          to: auth_info.email,
          kind: "signup_verification",
          subject: "Verify your email to finish sign-in",
          body: signup_body(user, auth_info, link_request, token)
        )
      end

      private

      def merge_body(user, auth_info, request, token)
        <<~BODY
          A sign-in attempt from #{auth_info.provider} (uid #{auth_info.uid})
          matched the email #{auth_info.email || '(none)'} on your account
          #{user.email}.

          Provider email status: #{auth_info.email_status}
          Required confirmation: #{request.required_confirmation}

          If you started this, confirm here:
            /oauth/link/confirm?request_id=#{request.id}&token=#{token}

          If you did NOT start this, no action is needed and no link is made.
          Review pending requests: /account/link-requests
        BODY
      end

      def signup_body(_user, auth_info, request, token)
        <<~BODY
          Finish creating your account by proving control of this mailbox:
            /oauth/signup/verify?request_id=#{request.id}&token=#{token}

          Provider: #{auth_info.provider} (email status: #{auth_info.email_status})
        BODY
      end

      def record(to:, kind:, subject:, body:)
        message = { to: to, kind: kind, subject: subject, body: body, at: Time.now.utc }
        @deliveries << message
        @logger.info("[#{kind}] to=#{to} subject=#{subject.inspect}")
        message
      end
    end
  end
end
