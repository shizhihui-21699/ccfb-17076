#!/usr/bin/env ruby
# frozen_string_literal: true

# Historical merge audit CLI.
#
# Usage:
#   bin/audit_merges.rb --db DB_PATH            # report only (dry run)
#   bin/audit_merges.rb --db DB_PATH --apply    # quarantine critical/high rows
#   bin/audit_merges.rb --db DB_PATH --json     # machine-readable report
#
# The report reconstructs every OAuth identity, grades legacy auto-merges by
# whether the provider could have verified the email, and (with --apply) flips
# risky rows to quarantined so they can no longer start sessions.

require "optparse"
require "json"
require_relative "../lib/oauth_login"

options = { apply: false, json: false }
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} --db PATH [--apply] [--json]"
  opts.on("--db PATH", "sqlite database path") { |v| options[:db] = v }
  opts.on("--apply", "quarantine risky identities (default: dry run)") do
    options[:apply] = true
  end
  opts.on("--json", "emit JSON instead of a text report") { options[:json] = true }
  opts.on("-h", "--help") { puts opts; exit }
end
parser.parse!(ARGV)

raise OptionParser::MissingArgument, "--db is required" unless options[:db]

OAuthLogin::Database.connect!(options[:db])
service = OAuthLogin::Services::HistoricalAuditService.new
findings = service.audit

rows = findings.map do |f|
  {
    severity: f.severity,
    identity_id: f.identity.id,
    user_id: f.identity.user_id,
    user_email: f.identity.user.email,
    provider: f.identity.provider,
    uid: f.identity.uid,
    link_method: f.identity.link_method,
    email_at_link: f.identity.email_at_link,
    email_status_at_link: f.identity.email_status_at_link,
    quarantined: f.identity.quarantined?,
    reason: f.reason
  }
end

if options[:json]
  puts JSON.pretty_generate(rows)
else
  puts "Historical OAuth merge audit (#{options[:apply] ? 'APPLY' : 'dry run'})"
  puts "=" * 72
  groups = rows.group_by { |r| r[:severity] }
  %w[critical high info].each do |severity|
    list = groups[severity] || []
    puts "\n[#{severity.upcase}] #{list.size} finding(s)"
    list.each do |r|
      puts "  identity##{r[:identity_id]} user##{r[:user_id]} " \
           "(#{r[:user_email]}) via #{r[:provider]}:#{r[:uid]}"
      puts "    method=#{r[:link_method]} status=#{r[:email_status_at_link].inspect} " \
           "quarantined=#{r[:quarantined]}"
      puts "    -> #{r[:reason]}"
    end
  end
end

actionable = service.remediate(findings, apply: options[:apply])
warn "\n#{options[:apply] ? 'Quarantined' : 'Would quarantine'} " \
     "#{actionable.size} identity/identities."
exit(findings.any? { |f| f.severity == "critical" } ? 2 : 0)
