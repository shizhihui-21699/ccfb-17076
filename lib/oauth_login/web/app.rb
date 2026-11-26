# frozen_string_literal: true

require "rack"
require "json"
require "openssl"
require "base64"
require "securerandom"
require_relative "../../oauth_login"

module OAuthLogin
  class Unauthorized < StandardError; end
  class BadRequest < StandardError; end

  # Minimal Rack application demonstrating the secure flow end to end.
  #
  # A real deployment would replace the fixture callback with actual OAuth
  # token exchanges; everything after the callback (normalization, login
  # decision, confirmation state machine) is production-shaped and is the code
  # this project exists to get right.
  #
  # Routes:
  #   GET  /                              - status / whoami
  #   POST /oauth/callback                - fixture/real provider callback
  #   GET  /oauth/link/confirm            - email leg of a merge request
  #   POST /oauth/link/confirm            - authenticated leg (holder session)
  #   POST /oauth/link/decline            - holder rejects
  #   GET  /account/link-requests         - pending requests for the holder
  #   GET  /oauth/signup/verify           - new-signup email verification
  #   POST /login                         - password/session login (stub)
  #   POST /logout
  class WebApp
    SESSION_COOKIE = "oauth_login_session"

    def initialize(mailer: Mailer::LogMailer.new, session_store: CookieSession.new)
      @mailer = mailer
      @sessions = session_store
    end

    def call(env)
      request = Rack::Request.new(env)
      route(request)
    rescue ProviderRegistry::UnknownProvider => e
      json(400, error: "unknown provider", message: e.message)
    rescue OAuthLogin::IdentityConflict => e
      json(409, error: "identity_conflict", message: e.message)
    rescue Services::LinkConfirmationService::ConfirmationError => e
      json(403, error: "confirmation_failed", message: e.message)
    rescue Unauthorized => e
      json(401, error: "authentication_required", message: e.message)
    rescue BadRequest => e
      json(400, error: "bad_request", message: e.message)
    rescue ActiveRecord::RecordNotFound
      json(404, error: "not_found")
    end

    private

    def route(request)
      key = [request.request_method, request.path_info]
      handler = ROUTES[key]
      return send(handler, request) if handler

      json(404, error: "not_found")
    end

    ROUTES = {
      ["GET",  "/"]                     => :whoami,
      ["POST", "/oauth/callback"]       => :oauth_callback,
      ["GET",  "/oauth/link/confirm"]   => :email_leg,
      ["POST", "/oauth/link/confirm"]   => :login_leg,
      ["POST", "/oauth/link/decline"]   => :decline,
      ["GET",  "/account/link-requests"] => :list_requests,
      ["GET",  "/oauth/signup/verify"]  => :signup_verify,
      ["POST", "/login"]                => :password_login,
      ["POST", "/logout"]               => :logout
    }.freeze

    def oauth_callback(request)
      provider = request.params["provider"]
      payload = parse_payload(request.params["payload"])
      result = OAuthLogin.login(provider, payload, mailer: @mailer)

      body = {
        outcome: result.outcome,
        reason: result.reason,
        user: result.user && serialize_user(result.user),
        link_request: result.link_request && serialize_request(result.link_request)
      }

      case result.outcome
      when :session_created, :signup_ready
        session = issue_session(result.user)
        json(200, body, "set-cookie" => session)
      when :quarantined
        json(403, body)
      when :identity_conflict
        json(409, body)
      else
        # merge_requested / signup_pending: deliberately NO session cookie.
        json(202, body.merge(
               note: "no session created; confirmation required out of band"
             ))
      end
    end

    # GET: clicked from the email -> proves mailbox control.
    def email_leg(request)
      request_record = Services::LinkConfirmationService.new
                       .confirm_by_email(request.params["token"].to_s)
      if request_record.needs_login_confirmation?
        html(200, "Email confirmed. Please sign in to approve the link: " \
                  "/account/link-requests (#{request_record.id})")
      else
        html(200, "Your sign-in is confirmed. You may now log in.")
      end
    end

    # POST: holder authenticated in their own session approves the link.
    def login_leg(request)
      current = require_user(request)
      identity = Services::LinkConfirmationService.new.confirm_in_session(
        request_id: request.params["request_id"].to_i,
        current_user: current,
        raw_token: request.params["token"]
      )
      json(200, linked: serialize_identity(identity))
    end

    def decline(request)
      current = require_user(request)
      record = Services::LinkConfirmationService.new.decline(
        request_id: request.params["request_id"].to_i,
        current_user: current,
        reason: request.params["reason"] || "declined by account holder"
      )
      json(200, state: record.state)
    end

    def list_requests(request)
      current = require_user(request)
      records = AccountLinkRequest.pending.where(user_id: current.id)
      json(200, requests: records.map { |r| serialize_request(r) })
    end

    def signup_verify(request)
      request_record = Services::LinkConfirmationService.new
                       .confirm_by_email(request.params["token"].to_s)
      # New-signup requests carry email_token only; after the email leg the
      # identity is created and the user can log in normally.
      html(200, "Email verified (request #{request_record.id}). Please sign in.")
    end

    def password_login(request)
      user = User.find_by("lower(email) = ?", request.params["email"].to_s.downcase)
      # Stubbed credential check: this app's focus is OAuth, not passwords.
      unless user && request.params["password"] == "correct-horse-battery-staple"
        return json(401, error: "invalid_credentials")
      end

      json(200, { user: serialize_user(user) },
           "set-cookie" => issue_session(user))
    end

    def logout(request)
      @sessions.destroy(request)
      [200, cookie_header(@sessions.clear_cookie), [JSON.generate(ok: true)]]
    end

    def whoami(request)
      user = current_user(request)
      json(200, authenticated: !user.nil?, user: user && serialize_user(user))
    end

    # --- helpers ---------------------------------------------------------

    def require_user(request)
      current_user(request) or raise Unauthorized, "authentication_required"
    end

    def current_user(request)
      user_id = @sessions.user_id(request)
      user_id && User.find_by(id: user_id)
    end

    def issue_session(user)
      @sessions.issue(user)
    end

    def parse_payload(raw)
      return raw if raw.is_a?(Hash)
      JSON.parse(raw.to_s)
    rescue JSON::ParserError
      raise BadRequest, "payload must be a JSON object"
    end

    def serialize_user(user)
      { id: user.id, email: user.email, email_verified: user.email_verified }
    end

    def serialize_request(record)
      {
        id: record.id, provider: record.provider, uid: record.uid,
        email: record.email, email_status: record.email_status,
        required_confirmation: record.required_confirmation,
        state: record.state, expires_at: record.expires_at.iso8601
      }
    end

    def serialize_identity(identity)
      { id: identity.id, provider: identity.provider, uid: identity.uid,
        user_id: identity.user_id, link_method: identity.link_method }
    end

    def halt_json(status, payload)
      json(status, payload)
    end

    def json(status, payload, extra_headers = {})
      [status, { "content-type" => "application/json" }.merge(extra_headers),
       [JSON.generate(payload)]]
    end

    def cookie_header(cookie)
      { "set-cookie" => cookie }
    end
    def html(status, text)
      [status, { "content-type" => "text/plain; charset=utf-8" }, [text]]
    end
  end

  # Signed, HMAC-protected cookie session so identity cannot be forged by
  # editing the cookie. Kept dependency-free (stdlib OpenSSL).
  class CookieSession
    def initialize(secret: ENV.fetch("OAUTH_LOGIN_SESSION_SECRET",
                                     SecureRandom.hex(32)))
      @secret = secret
    end

    def issue(user)
      value = encode("user_id" => user.id, "issued_at" => Time.now.utc.iso8601)
      "#{WebApp::SESSION_COOKIE}=#{value}; HttpOnly; SameSite=Lax; Path=/"
    end

    def user_id(request)
      cookie = request.cookies[WebApp::SESSION_COOKIE]
      return nil unless cookie
      decode(cookie)&.dig("user_id")
    rescue StandardError
      nil
    end

    def clear_cookie
      "#{WebApp::SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    end

    def destroy(request)
      # Rack reads cookies from the request; clearing happens via the
      # Set-Cookie header emitted by the caller. Nothing to delete server-side
      # because sessions are stateless signed cookies.
      request
    end

    private

    def encode(data)
      payload = Base64.urlsafe_encode64(JSON.generate(data), padding: false)
      "#{payload}.#{sign(payload)}"
    end

    def decode(cookie)
      payload, signature = cookie.split(".", 2)
      return nil unless payload && signature
      return nil unless secure_compare(signature, sign(payload))

      JSON.parse(Base64.urlsafe_decode64(payload))
    end

    def sign(payload)
      OpenSSL::HMAC.hexdigest("SHA256", @secret, payload)
    end

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      r = 0
      b.each_byte.with_index { |byte, i| r |= byte ^ a.getbyte(i) }
      r.zero?
    end
  end
end
