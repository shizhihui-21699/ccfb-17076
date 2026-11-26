# frozen_string_literal: true

module OAuthLogin
  # Normalized representation of what an OAuth/OIDC provider told us.
  #
  # Every provider-specific adapter (see OAuthLogin::Adapters) converts its own
  # payload into this structure so the rest of the application never has to know
  # that Google uses a boolean, Apple uses a string, GitHub requires a second API
  # call and WeChat does not return an email at all.
  #
  # +email_status+ is the security-critical field. It can only ever be one of:
  #
  #   :verified       - the provider asserts it owns and verified this mailbox
  #   :unverified     - the provider returned the email but explicitly says it
  #                     has NOT been verified
  #   :not_provided   - the provider gives us no verification signal at all
  #                     (treat as unverified; the distinction is recorded so we
  #                     can explain the decision in logs and on the UI)
  #   :not_requested  - the provider did not return an email (scope not granted,
  #                     or the provider simply has no email, e.g. WeChat)
  class AuthInfo
    attr_reader :provider, :uid, :email, :email_status, :raw, :metadata

    def initialize(provider:, uid:, email: nil, email_status: :not_requested,
                   raw: {}, metadata: {})
      raise ArgumentError, "provider is required" if provider.nil? || provider.to_s.empty?
      raise ArgumentError, "uid is required" if uid.nil? || uid.to_s.empty?
      raise ArgumentError, "unknown email_status #{email_status.inspect}" unless
        %i[verified unverified not_provided not_requested].include?(email_status)

      @provider = provider.to_s
      @uid = uid.to_s
      @email = normalize_email(email)
      @email_status = email_status
      @raw = raw
      @metadata = metadata
      freeze
    end

    def email?
      !@email.nil?
    end

    # The ONLY place that may treat the mailbox as controlled by the person
    # clicking through the OAuth flow. Everything else must ask this method and
    # route through an explicit confirmation instead of trusting the email.
    def email_verified?
      @email_status == :verified
    end

    def to_s
      "#<#{self.class.name} provider=#{provider} uid=#{uid} " \
        "email=#{email || '(none)'} email_status=#{email_status}>"
    end

    private

    def normalize_email(addr)
      return nil if addr.nil?
      addr = addr.to_s.strip.downcase
      addr.empty? ? nil : addr
    end
  end
end
