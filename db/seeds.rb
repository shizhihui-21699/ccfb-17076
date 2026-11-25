# 演示 + 测试用种子数据：
# 1. 受害者站内账号（密码注册，邮箱已验证）
# 2. 攻击者在“不验证邮箱”的 Facebook 上注册了受害者邮箱
# 3. 修复前的脏数据：该 Facebook 身份已被旧逻辑自动合并进受害者账号
# 4. 对照组：Google 已验证邮箱的正常合并、GitHub 已验证主邮箱
# 5. 无验证平台的普通用户
ActiveRecord::Base.transaction do
  # 顺序受外键约束：先删引用方
  SecurityEvent.delete_all
  MergeRequest.delete_all
  Identity.delete_all
  User.delete_all

  victim = User.create!(email: 'victim@example.com', email_verified: true,
                        password_digest: BCrypt::Password.create('victim-pass-123'),
                        display_name: 'Victim')

  # 旧逻辑留下的高危合并：Facebook 不验证邮箱
  Identity.create!(user: victim, provider: 'facebook', provider_uid: 'fb-attacker-001',
                   provider_email: 'victim@example.com', email_verification: 'unknown',
                   status: 'active', linked_at: 30.days.ago)

  # 对照组：Google 明确验证过邮箱的历史合并（低风险）
  Identity.create!(user: victim, provider: 'google', provider_uid: 'g-victim-001',
                   provider_email: 'victim@example.com', email_verification: 'verified',
                   status: 'active', linked_at: 20.days.ago)

  # 只有单一凭据的账号（medium）
  carol = User.create!(email: 'carol@example.com', email_verified: false,
                       display_name: 'Carol')
  Identity.create!(user: carol, provider: 'linkedin', provider_uid: 'li-carol-1',
                   provider_email: 'carol@example.com', email_verification: 'unknown',
                   status: 'active', linked_at: 10.days.ago)

  # mock 授权服务器里的第三方账号池
  registry = MockOAuthRegistry.instance
  registry.reset_all!
  registry.seed('facebook', 'fb-attacker-001',
                uid: 'fb-attacker-001', email: 'victim@example.com',
                name: 'I Am Victim (attacker)')
  # 一个全新的攻击者身份（未在站内留下任何绑定），用于演示新逻辑下的合并请求流程
  registry.seed('facebook', 'fb-attacker-002',
                uid: 'fb-attacker-002', email: 'victim@example.com',
                name: 'I Am Victim Too (attacker)')
  registry.seed('google', 'g-victim-001',
                uid: 'g-victim-001', email: 'victim@example.com',
                email_verified: true, name: 'Real Victim')
  registry.seed('google', 'g-newbie-002',
                uid: 'g-newbie-002', email: 'newbie@example.com',
                email_verified: true, name: 'Newbie')
  registry.seed('google', 'g-unverified-003',
                uid: 'g-unverified-003', email: 'victim@example.com',
                email_verified: false, name: 'Spoof Try')
  registry.seed('github', 'gh-1001',
                uid: 'gh-1001', name: 'Octo Cat', email: 'octo@example.com',
                emails: [
                  { email: 'octo@example.com', primary: true, verified: true },
                  { email: 'octo-private@example.com', primary: false, verified: true }
                ])
  registry.seed('apple', 'apple-2001',
                uid: 'apple-2001', name: 'Apple User',
                email: 'appleuser@example.com', email_verified: 'true')
  registry.seed('twitter', 'tw-3001',
                uid: 'tw-3001', name: 'No Email User', login: 'noemail')
  registry.seed('microsoft', 'ms-4001',
                uid: 'ms-4001', name: 'MS User', email: 'msuser@example.com')
  registry.seed('linkedin', 'li-carol-1',
                uid: 'li-carol-1', name: 'Carol', email: 'carol@example.com')

  puts '种子数据就绪：'
  puts "  受害者账号: #{victim.email}（密码 victim-pass-123）"
  puts '  攻击身份: facebook:fb-attacker-001 携带受害者邮箱但验证状态 unknown'
end
