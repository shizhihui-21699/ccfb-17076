# frozen_string_literal: true

require "active_record"

module OAuthLogin
  # Handles connecting ActiveRecord and creating the schema. Kept framework
  # agnostic so the same code runs under Rack, a Rake task or the test suite.
  module Database
    SCHEMA_VERSION = 2026_11_27_000_000

    class << self
      # @param config [Hash] ActiveRecord-style connection config, or a path
      #   to a sqlite file, or ":memory:"
      def connect!(config)
        config = sqlite_config(config) unless config.is_a?(Hash)
        ActiveRecord::Base.establish_connection(config)
        ActiveRecord::Base.logger = config[:logger]
        ActiveRecord::Base.connection
      end

      def create_schema!
        connection = ActiveRecord::Base.connection

        connection.create_table :users, force: :cascade do |t|
          t.string  :email, null: false
          t.boolean :email_verified, null: false, default: false
          t.string  :password_digest
          t.string  :display_name
          t.timestamps null: false
          t.index :email, unique: true
        end

        connection.create_table :oauth_identities, force: :cascade do |t|
          t.references :user, null: false, foreign_key: true
          t.string  :provider, null: false
          t.string  :uid, null: false
          # Snapshot of what the provider asserted at link time, kept for
          # forensics / the historical-merge audit.
          t.string  :email_at_link
          t.string  :email_status_at_link
          t.boolean :provider_email_verified, null: false, default: false
          # Quarantine flips true when the audit tool distrusts an old link.
          # A quarantined identity cannot start a session.
          t.boolean :quarantined, null: false, default: false
          t.string  :quarantine_reason
          # How the link was established. The dangerous legacy value is
          # "auto_email_match"; new links are "confirmed" or "signup".
          t.string  :link_method, null: false, default: "confirmed"
          t.timestamps null: false
          t.index %i[provider uid], unique: true
          t.index :provider
        end

        connection.create_table :account_link_requests, force: :cascade do |t|
          t.references :user, null: false, foreign_key: true
          t.string  :provider, null: false
          t.string  :uid, null: false
          t.string  :email
          t.string  :email_status, null: false
          # What the holder must do. "email_token": prove control of the
          # provider-supplied mailbox; "login_token": prove control of the
          # existing account; "both": untrusted provider + existing account.
          t.string  :required_confirmation, null: false
          t.string  :state, null: false, default: "pending"
          t.string  :token_digest
          # Explicit legs of a multi-step confirmation. Both must be true
          # before a "both" request may create the identity.
          t.boolean :email_proven, null: false, default: false
          t.boolean :login_proven, null: false, default: false
          t.datetime :expires_at, null: false
          t.datetime :confirmed_at
          t.string  :confirmed_by_user_id
          t.text    :decline_reason
          t.timestamps null: false
          t.index %i[provider uid]
          t.index :state
        end

        connection.create_table :audit_events, force: :cascade do |t|
          t.string  :event_type, null: false
          t.string  :provider
          t.string  :uid
          t.references :user
          t.string  :email
          t.string  :email_status
          t.text    :detail
          t.timestamps null: false
          t.index :event_type
          t.index %i[provider uid]
        end

        # The unique index on oauth_identities(provider, uid) is the
        # schema-level backstop ensuring one provider identity can never be
        # bound to two local users, even under a race.
      end

      def reset!
        connection = ActiveRecord::Base.connection
        connection.disable_referential_integrity do
          connection.tables.each do |table|
            connection.drop_table(table)
          end
        end
        create_schema!
      end

      private

      def sqlite_config(path_or_spec)
        {
          adapter: "sqlite3",
          database: path_or_spec.to_s,
          pool: 5,
          timeout: 5000
        }
      end
    end
  end
end
