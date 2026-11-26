#!/usr/bin/env ruby
# frozen_string_literal: true

# End-to-end demonstration of the incident attack against the redesigned flow.
# Runs entirely in-memory and prints each step's decision.

require_relative "../lib/oauth_login"

OAuthLogin::Database.connect!(":memory:")
OAuthLogin::Database.create_schema!
mailer = OAuthLogin::Mailer::LogMailer.new
login = OAuthLogin::Services::LoginService.new(mailer: mailer)
confirmer = OAuthLogin::Services::LinkConfirmationService.new

victim = OAuthLogin::User.create!(email: "victim@example.com", email_verified: true)
puts "1. Victim has an in-site account: #{victim.email}"
puts

puts "2. Attacker registers victim@example.com on Facebook (no verification)"
puts "   and completes Facebook OAuth into our site."
attack = login.call(
  OAuthLogin::Services::ProviderExchange.parse(
    "facebook", "id" => "fb-attacker", "email" => "victim@example.com"
  )
)
puts "   -> outcome: #{attack.outcome}"
puts "   -> session created for victim? #{attack.session?}"
puts "   -> identities now on victim: " \
     "#{OAuthLogin::OAuthIdentity.where(user_id: victim.id).count}"
puts "   -> confirmation required: " \
     "#{attack.link_request.required_confirmation} (mailbox + account holder)"
puts

puts "3. Attacker controls the fake mailbox, so they click the email link."
confirmer.confirm_by_email(attack.raw_token)
puts "   -> email leg recorded; identities on victim still: " \
     "#{OAuthLogin::OAuthIdentity.where(user_id: victim.id).count}"
puts

puts "4. Attacker tries to finish without the victim's session."
begin
  confirmer.confirm_in_session(
    request_id: attack.link_request.id,
    current_user: OAuthLogin::User.create!(email: "attacker@evil.com",
                                           email_verified: false)
  )
rescue OAuthLogin::Services::LinkConfirmationService::WrongUser => e
  puts "   -> blocked: #{e.message}"
end
puts

puts "5. Victim logs in normally and reviews the pending request."
identity = confirmer.confirm_in_session(
  request_id: attack.link_request.id, current_user: victim
)
puts "   -> only now is an identity created: #{identity}"
puts "   -> link method: #{identity.link_method}"
puts

puts "RESULT: the attacker never reached the victim's account. The link " \
     "exists solely because the verified holder approved it."
