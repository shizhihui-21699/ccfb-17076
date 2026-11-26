#!/usr/bin/env ruby
# frozen_string_literal: true

# Creates the schema and seeds a realistic mix of:
#   * legacy auto-merged identities (the rows the audit must find), including
#     the exact attack pattern from the incident: an unverified-provider
#     identity merged onto a victim's account by bare email match;
#   * healthy post-fix identities created via confirmed linking.
#
# Usage: bin/setup_and_seed.rb DB_PATH

require_relative "../lib/oauth_login"

db_path = ARGV.fetch(0) { "db/development.sqlite3" }
OAuthLogin::Database.connect!(db_path)
OAuthLogin::Database.reset!

models = OAuthLogin

victim = models::User.create!(email: "victim@example.com", email_verified: true)
alice  = models::User.create!(email: "alice@example.com", email_verified: true)
bob    = models::User.create!(email: "bob@example.com", email_verified: false)

# --- Legacy rows (as the old auto-merge code would have left them) --------

# The incident: attacker registered victim@example.com on a provider that
# does not verify email, and the old code auto-merged into the victim.
models::OAuthIdentity.create!(
  user: victim, provider: "facebook", uid: "fb-attacker-001",
  email_at_link: "victim@example.com", email_status_at_link: nil,
  provider_email_verified: false, link_method: "auto_email_match"
)

# Same shape on Twitter, another no-verification-signal provider.
models::OAuthIdentity.create!(
  user: alice, provider: "twitter", uid: "tw-9988",
  email_at_link: "alice@example.com", email_status_at_link: nil,
  provider_email_verified: false, link_method: "auto_email_match"
)

# Legacy Google merge with no surviving snapshot: cannot prove verification.
models::OAuthIdentity.create!(
  user: bob, provider: "google", uid: "g-legacy-77",
  email_at_link: "bob@example.com", email_status_at_link: nil,
  provider_email_verified: false, link_method: "legacy_unknown"
)

# Legacy merge that happens to have a trustworthy stored snapshot.
models::OAuthIdentity.create!(
  user: alice, provider: "google", uid: "g-good-44",
  email_at_link: "alice@example.com", email_status_at_link: "verified",
  provider_email_verified: true, link_method: "auto_email_match"
)

# --- Healthy post-fix rows ------------------------------------------------

models::OAuthIdentity.create!(
  user: victim, provider: "google", uid: "g-victim-21",
  email_at_link: "victim@example.com", email_status_at_link: "verified",
  provider_email_verified: true, link_method: "confirmed"
)
models::OAuthIdentity.create!(
  user: bob, provider: "github", uid: "gh-bob-7",
  email_at_link: "bob@example.com", email_status_at_link: "verified",
  provider_email_verified: true, link_method: "signup"
)

models::AuditEvent.log!(
  "identity_linked",
  provider: "facebook", uid: "fb-attacker-001", user: victim,
  email: "victim@example.com", email_status: nil,
  detail: "method=auto_email_match (legacy)"
)

puts "Seeded #{models::User.count} users and " \
     "#{models::OAuthIdentity.count} oauth identities into #{db_path}"
