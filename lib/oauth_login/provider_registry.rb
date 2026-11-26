# frozen_string_literal: true

require_relative "adapters/base"
require_relative "adapters/google_adapter"
require_relative "adapters/apple_adapter"
require_relative "adapters/github_adapter"
require_relative "adapters/microsoft_adapter"
require_relative "adapters/facebook_adapter"
require_relative "adapters/twitter_wechat_adapters"

module OAuthLogin
  # Lookup table of supported providers plus the documentation-driven policy
  # describing how much their email signal can be trusted.
  #
  # The policy is deliberately separate from the adapters: an adapter answers
  # "what did this provider say about THIS response"; the registry answers
  # "how should our product treat that class of provider in general". If a
  # provider improves its API tomorrow we update one table, and the change is
  # visible in audit logs and tests.
  module ProviderRegistry
    ADAPTERS = {
      "google"    => Adapters::GoogleAdapter,
      "apple"     => Adapters::AppleAdapter,
      "github"    => Adapters::GithubAdapter,
      "microsoft" => Adapters::MicrosoftAdapter,
      "facebook"  => Adapters::FacebookAdapter,
      "twitter"   => Adapters::TwitterAdapter,
      "wechat"    => Adapters::WechatAdapter
    }.freeze

    # Static, human-reviewed trust summary. Even +trusts_verified_email: true+
    # providers still go through holder confirmation on a *merge* -- this flag
    # only lets a brand-new signup skip our own verification email.
    PROFILES = {
      "google"    => { trusts_verified_email: true,  signal: "OIDC email_verified boolean" },
      "apple"     => { trusts_verified_email: true,  signal: "OIDC email_verified string; email only on first auth" },
      "github"    => { trusts_verified_email: true,  signal: "separate /user/emails verified flag; /user email is untrusted" },
      "microsoft" => { trusts_verified_email: false, signal: "email_verified claim often absent; upn/preferred_username are not proof" },
      "facebook"  => { trusts_verified_email: false, signal: "no verification flag exposed to apps" },
      "twitter"   => { trusts_verified_email: false, signal: "no verification flag exposed to apps" },
      "wechat"    => { trusts_verified_email: false, signal: "no email returned at all" }
    }.freeze

    class UnknownProvider < StandardError; end

    class << self
      def supported?(provider)
        ADAPTERS.key?(provider.to_s)
      end

      def adapter_for(provider)
        klass = ADAPTERS.fetch(provider.to_s) do
          raise UnknownProvider, "no adapter registered for #{provider.inspect}"
        end
        klass.new
      end

      def profile_for(provider)
        PROFILES.fetch(provider.to_s) do
          raise UnknownProvider, "no trust profile for #{provider.inspect}"
        end
      end

      # Convenience used by the login service. Note this is a *capability*
      # check; every merge still needs explicit holder confirmation regardless.
      def trusts_verified_email?(provider)
        profile_for(provider)[:trusts_verified_email]
      end

      def providers
        ADAPTERS.keys
      end
    end
  end
end
