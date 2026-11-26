# frozen_string_literal: true

# Public entry point. Require this file to get the whole OAuth login domain.
require_relative "oauth_login/auth_info"
require_relative "oauth_login/database"
require_relative "oauth_login/provider_registry"
require_relative "oauth_login/mailer"

require_relative "oauth_login/models/user"
require_relative "oauth_login/models/oauth_identity"
require_relative "oauth_login/models/account_link_request"
require_relative "oauth_login/models/audit_event"

require_relative "oauth_login/services/login_service"
require_relative "oauth_login/services/link_confirmation_service"
require_relative "oauth_login/services/provider_exchange"
require_relative "oauth_login/services/historical_audit_service"

module OAuthLogin
  VERSION = "1.0.0"

  class << self
    # Convenience wrapper for the common path: raw provider payload in,
    # LoginResult out.
    def login(provider, raw_payload, mailer: nil)
      auth_info = Services::ProviderExchange.parse(provider, raw_payload)
      Services::LoginService.new(mailer: mailer).call(auth_info)
    end
  end
end
