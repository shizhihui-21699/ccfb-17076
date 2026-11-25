# 端到端冒烟（rack-test 驱动完整 Rails 中间件栈）：
# 验证“邮箱相同不自动合并、必须持有人确认”的完整攻击链。
# 用法：RAILS_ENV=test ruby tmp/smoke_integration.rb
ENV['RAILS_ENV'] = 'test'
require_relative '../config/environment'
require 'rack/test'

# 独立脚本里 mailer 渲染会与 rack/test 的 request 方法冲突；
# 冒烟只验证安全逻辑、不验证邮件排版，这里用 null 投递（生产/test 环境各自配置）
ActionMailer::Base.delivery_method = :null
ActionMailer::Base.deliveries.clear

include Rack::Test::Methods
def app
  Rails.application
end

$pass = 0
$fail = 0
def check(desc, expected, actual)
  if expected == actual
    puts "PASS: #{desc} (#{actual})"; $pass += 1
  else
    puts "FAIL: #{desc} expected=[#{expected}] actual=[#{actual}]"; $fail += 1
  end
end

def token_from(body)
  body[/name="authenticity_token" value="([^"]+)"/, 1]
end

[SecurityEvent, MergeRequest, Identity, User].each(&:delete_all)
MockOAuthRegistry.instance.reset!

# 受害者站内账号
victim = User.create!(email: 'victim@example.com', email_verified: true,
                      password_digest: BCrypt::Password.create('victim-pass-123'),
                      display_name: 'Victim')
# mock 第三方：攻击者在不验证邮箱的平台注册了受害者邮箱
reg = MockOAuthRegistry.instance
reg.seed('facebook', 'fb-evil-new', uid: 'fb-evil-new',
         email: 'victim@example.com', name: 'fake victim')
reg.seed('facebook', 'fb-old-quarantine', uid: 'fb-old-quarantine',
         email: 'victim@example.com', name: 'old')
reg.seed('google', 'g-unverified', uid: 'g-unverified',
         email: 'victim@example.com', email_verified: false, name: 'spoof')
# 历史脏数据：旧逻辑自动合并、已被审计隔离的身份
Identity.create!(user: victim, provider: 'facebook', provider_uid: 'fb-old-quarantine',
                 provider_email: 'victim@example.com', email_verification: 'unknown',
                 status: 'quarantined', quarantine_reason: 'legacy-audit',
                 linked_at: 30.days.ago)

def complete_oauth(provider, uid, session = self)
  session.get "/auth/#{provider}"
  state = URI.parse(session.last_response.location).query.split('&')
               .find { |p| p.start_with?('state=') }.sub('state=', '')
  code = MockOAuthRegistry.instance.issue_code(provider, uid)
  session.get "/auth/#{provider}/callback", code: code, state: state
end

# 独立会话 = 全新访客（独立 cookie 存储）
def new_session
  Rack::Test::Session.new(Rack::MockSession.new(Rails.application))
end

puts '=== 1. 攻击者用 Facebook 受害者邮箱登录：不进账号，只生成合并请求 ==='
complete_oauth('facebook', 'fb-evil-new')
check '回调重定向到首页', 'http://example.org/', last_response.location
check '无 identity 产生', 0, Identity.where(provider_uid: 'fb-evil-new').count
mr = MergeRequest.find_by(provider_uid: 'fb-evil-new')
check '生成 pending 合并请求', 'pending', mr&.status
check '记录验证状态 unknown', 'unknown', mr&.email_verification
check '目标是受害者账号', victim.id, mr&.target_user_id

puts '=== 2. 受害者密码登录后确认合并 ==='
get '/login'
post '/login', authenticity_token: token_from(last_response.body),
                email: 'victim@example.com', password: 'victim-pass-123'
check '受害者登录成功', 302, last_response.status
get '/account'
check '账号页可访问', 200, last_response.status
post "/account/merge_requests/#{mr.id}/confirm",
     authenticity_token: token_from(last_response.body)
check '确认请求 302', 302, last_response.status
check '请求变 confirmed', 'confirmed', mr.reload.status
ident = Identity.find_by(provider_uid: 'fb-evil-new')
check '确认后建立 active identity', 'active', ident&.status
check 'identity 归属受害者', victim.id, ident&.user_id

puts '=== 3. 确认后该 Facebook 身份可直接登录受害者账号 ==='
s3 = new_session
complete_oauth('facebook', 'fb-evil-new', s3)
check '已绑定身份登录进入账号页', 'http://example.org/account', s3.last_response.location

puts '=== 4. 被隔离的历史身份登录被拒 ==='
s4 = new_session
complete_oauth('facebook', 'fb-old-quarantine', s4)
check '隔离身份重定向到首页', 'http://example.org/', s4.last_response.location
check '记录隔离拦截事件', 1,
      SecurityEvent.where(event_type: 'oauth_login_blocked_quarantined').count

puts '=== 5. Google 未验证邮箱撞号同样只产生请求 ==='
s5 = new_session
complete_oauth('google', 'g-unverified', s5)
check '未验证身份不直接登录', 'http://example.org/', s5.last_response.location
check 'Google 状态为 unverified', 'unverified',
      MergeRequest.find_by(provider_uid: 'g-unverified')&.email_verification

puts '=== 6. state 伪造被拒 ==='
s6 = new_session
s6.get '/auth/facebook'
code = MockOAuthRegistry.instance.issue_code('facebook', 'fb-evil-new')
before = [User.count, Identity.count, MergeRequest.count]
s6.get '/auth/facebook/callback', code: code, state: 'forged'
check '伪造 state 不产生数据变化', before, [User.count, Identity.count, MergeRequest.count]

puts
puts "结果：#{$pass} 通过 / #{$fail} 失败"
exit($fail.zero? ? 0 : 1)
