namespace :security do
  desc '排查历史上按“邮箱相同”自动合并的第三方身份（默认只出报告）'
  task :audit_legacy_merges, [:mode] => :environment do |_t, args|
    mode = args[:mode] || 'audit'
    findings = Audit::LegacyMergeAudit.run(mode: mode)

    puts "=== 历史合并排查（mode=#{mode}）==="
    if findings.empty?
      puts '未发现需要关注的身份。'
    else
      findings.group_by(&:risk).each do |risk, list|
        puts "\n[#{risk.upcase}] #{list.size} 条"
        list.each do |f|
          i = f.identity
          puts "  user##{i.user_id} #{i.provider}:#{i.provider_uid} " \
               "email=#{i.provider_email} verification=#{i.email_verification} " \
               "status=#{i.status}"
          puts "    → #{f.reason}"
        end
      end
    end

    counts = findings.group_by(&:risk).transform_values(&:count)
    puts "\n汇总：identities=#{Identity.count} " \
         "high=#{counts['high'].to_i} medium=#{counts['medium'].to_i} " \
         "low=#{counts['low'].to_i} mode=#{mode}"
  end

  desc '隔离高风险历史身份并为账号持有人生成确认请求：rake security:quarantine_risky_merges'
  task quarantine_risky_merges: :environment do
    findings = Audit::LegacyMergeAudit.run(mode: 'quarantine')
    puts "已隔离 #{findings.count { |f| f.risk == 'high' }} 条高风险身份，" \
         "其余 #{findings.count { |f| f.risk != 'high' }} 条仅记录。"
  end
end
