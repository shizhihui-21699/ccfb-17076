# frozen_string_literal: true

require "rack/test"
require_relative "test_helper"
require_relative "../lib/oauth_login/web/app"

# End-to-end HTTP-level proof that the OAuth callback never sets a session
# cookie on a contested merge, and only the holder's authenticated confirmation
# completes the link.
class WebFlowTest < Minitest::Test
  include Rack::Test::Methods
  include TestDB

  def app
    @app ||= OAuthLogin::WebApp.new
  end

  def setup
    super
    # Rebind the app's mailer to the per-test mailer after TestDB#setup ran.
    @app = OAuthLogin::WebApp.new(mailer: @mailer)
  end

  def test_callback_on_email_collision_returns_202_without_session_cookie
    create_user!("victim@example.com")

    post "/oauth/callback",
         provider: "facebook",
         payload: JSON.generate("id" => "fb-web",
                                "email" => "victim@example.com")

    assert_equal 202, last_response.status
    body = JSON.parse(last_response.body)
    assert_equal "merge_requested", body["outcome"]
    refute last_response.headers.key?("set-cookie"),
           "must not start a session for a contested email"
  end

  def test_full_web_merge_flow
    victim = create_user!("victim@example.com")

    post "/oauth/callback",
         provider: "facebook",
         payload: JSON.generate("id" => "fb-web2",
                                "email" => "victim@example.com")
    result = JSON.parse(last_response.body)
    request_id = result["link_request"]["id"]
    token = @mailer.deliveries.last[:body][/token=([^\s]+)/, 1]

    # Email leg (attacker could do this part).
    get "/oauth/link/confirm", request_id: request_id, token: token
    assert_equal 200, last_response.status

    # Login leg requires the holder's session.
    post "/login", email: "victim@example.com",
                   password: "correct-horse-battery-staple"
    cookie = last_response.headers["set-cookie"].split(";").first
    header "Cookie", cookie

    post "/oauth/link/confirm", request_id: request_id, token: token
    assert_equal 200, last_response.status
    linked = JSON.parse(last_response.body)["linked"]
    assert_equal victim.id, linked["user_id"]

    # And now the provider login works directly.
    header "Cookie", nil
    post "/oauth/callback",
         provider: "facebook",
         payload: JSON.generate("id" => "fb-web2",
                                "email" => "victim@example.com")
    assert_equal 200, last_response.status
    assert_equal "session_created", JSON.parse(last_response.body)["outcome"]
  end

  def test_login_leg_without_session_is_unauthorized
    create_user!("victim@example.com")
    post "/oauth/callback",
         provider: "facebook",
         payload: JSON.generate("id" => "fb-deny",
                                "email" => "victim@example.com")
    request_id = JSON.parse(last_response.body)["link_request"]["id"]

    post "/oauth/link/confirm", request_id: request_id
    assert_equal 401, last_response.status
  end

  def test_trusted_signup_sets_session_cookie
    post "/oauth/callback",
         provider: "google",
         payload: JSON.generate("sub" => "g-new",
                                "email" => "new@example.com",
                                "email_verified" => true)
    assert_equal 200, last_response.status
    assert last_response.headers["set-cookie"]&.include?(
      OAuthLogin::WebApp::SESSION_COOKIE
    )
  end

  def test_signed_session_cookie_is_tamper_resistant
    post "/login", email: create_user!("holder@example.com").email,
                   password: "correct-horse-battery-staple"
    raw_cookie = last_response.headers["set-cookie"].split(";").first
    name, value = raw_cookie.split("=", 2)

    # Flip a byte in the payload while preserving the cookie shape.
    payload, signature = value.split(".", 2)
    mutated = payload.dup
    mutated.setbyte(0, mutated.getbyte(0) ^ 0xff)
    header "Cookie", "#{name}=#{mutated}.#{signature}"
    get "/account/link-requests"
    assert_equal 401, last_response.status

    # And an entirely fabricated cookie is rejected too.
    header "Cookie", "#{name}=garbage.garbage"
    get "/"
    body = JSON.parse(last_response.body)
    assert_equal false, body["authenticated"]
  end
end
