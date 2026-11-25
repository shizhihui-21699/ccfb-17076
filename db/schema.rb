# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `rails
# db:schema:load`. When creating a new database, `rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema.define(version: 2026_01_01_000001) do

  create_table "identities", force: :cascade do |t|
    t.integer "user_id", null: false
    t.string "provider", null: false
    t.string "provider_uid", null: false
    t.string "provider_email"
    t.string "email_verification", default: "unknown", null: false
    t.string "status", default: "active", null: false
    t.string "quarantine_reason"
    t.datetime "linked_at"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.index ["provider", "provider_uid"], name: "index_identities_on_provider_and_provider_uid", unique: true
    t.index ["user_id", "provider"], name: "index_identities_on_user_id_and_provider"
    t.index ["user_id"], name: "index_identities_on_user_id"
  end

  create_table "merge_requests", force: :cascade do |t|
    t.integer "target_user_id", null: false
    t.string "provider", null: false
    t.string "provider_uid", null: false
    t.string "provider_email"
    t.string "email_verification", null: false
    t.string "status", default: "pending", null: false
    t.datetime "confirmed_at"
    t.datetime "rejected_at"
    t.text "decision_note"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.index ["provider", "provider_uid", "target_user_id", "status"], name: "idx_merge_requests_dedup"
    t.index ["target_user_id"], name: "index_merge_requests_on_target_user_id"
  end

  create_table "security_events", force: :cascade do |t|
    t.string "event_type", null: false
    t.integer "user_id"
    t.integer "identity_id"
    t.integer "merge_request_id"
    t.string "provider"
    t.string "ip_address"
    t.text "detail"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.index ["created_at"], name: "index_security_events_on_created_at"
    t.index ["event_type"], name: "index_security_events_on_event_type"
    t.index ["identity_id"], name: "index_security_events_on_identity_id"
    t.index ["merge_request_id"], name: "index_security_events_on_merge_request_id"
    t.index ["user_id"], name: "index_security_events_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "email", null: false
    t.boolean "email_verified", default: false, null: false
    t.string "password_digest"
    t.string "display_name"
    t.datetime "created_at", precision: 6, null: false
    t.datetime "updated_at", precision: 6, null: false
    t.index ["email"], name: "index_users_on_email", unique: true
  end

  add_foreign_key "identities", "users"
  add_foreign_key "merge_requests", "users", column: "target_user_id"
  add_foreign_key "security_events", "users"
end
