class CreateAllTables < ActiveRecord::Migration[6.0]
  def change
    create_table :users do |t|
      t.string :email, null: false
      t.boolean :email_verified, null: false, default: false
      t.string :password_digest
      t.string :display_name
      t.timestamps
    end
    add_index :users, :email, unique: true

    create_table :identities do |t|
      t.references :user, null: false, foreign_key: true
      t.string :provider, null: false
      t.string :provider_uid, null: false
      t.string :provider_email
      # 合并那一刻 provider 邮箱的验证状态快照：verified / unverified / unknown
      t.string :email_verification, null: false, default: 'unknown'
      # active 正常；quarantined 被历史排查任务隔离，登录时拒绝并提示
      t.string :status, null: false, default: 'active'
      t.string :quarantine_reason
      t.datetime :linked_at
      t.timestamps
    end
    add_index :identities, [:provider, :provider_uid], unique: true
    add_index :identities, [:user_id, :provider]

    create_table :merge_requests do |t|
      t.references :target_user, null: false, foreign_key: { to_table: :users }
      t.string :provider, null: false
      t.string :provider_uid, null: false
      t.string :provider_email
      t.string :email_verification, null: false
      t.string :status, null: false, default: 'pending' # pending/confirmed/rejected/dismissed
      t.datetime :confirmed_at
      t.datetime :rejected_at
      t.text :decision_note
      t.timestamps
    end
    add_index :merge_requests, [:provider, :provider_uid, :target_user_id, :status],
              name: 'idx_merge_requests_dedup'

    create_table :security_events do |t|
      t.string :event_type, null: false
      t.references :user, foreign_key: true
      t.references :identity
      t.references :merge_request
      t.string :provider
      t.string :ip_address
      t.text :detail
      t.timestamps
    end
    add_index :security_events, :event_type
    add_index :security_events, :created_at
  end
end
