require 'test_helper'

# 攻击场景的端到端复现：这是本次修复的核心回归测试
class AccountTakeoverFlowTest < ActionDispatch::IntegrationTest
  setup do
    @victim = User.create!(email: 'victim@example.com', email_verified: true,
                           display_name: 'Victim')
    seed_password(@victim, 'victim-pass-123')
  end

  test '攻击者用不验证邮箱平台上的受害者邮箱登录，无法进入受害者账号' do
    code = seed_provider_account('facebook', 'fb-evil-1',
                                 email: 'victim@example.com', name: 'fake')

    assert_difference -> { User.count } => 0,
                      -> { Identity.count } => 0,
                      -> { MergeRequest.count } => 1 do
      complete_oauth_flow('facebook', code)
    end

    # 没有建立会话
    assert_nil session[:user_id]
    assert_redirected_to root_path

    mr = MergeRequest.last
    assert_equal 'pending', mr.status
    assert_equal @victim.id, mr.target_user_id
    assert_equal 'unknown', mr.email_verification
    assert_equal 'fb-evil-1', mr.provider_uid

    # 给受害者发了确认邮件，且邮件文案标明未验证风险
    mail = ActionMailer::Base.deliveries.last
    assert_equal ['victim@example.com'], mail.to
    assert_match(/未经平台验证/, mail.subject)
  end

  test '受害者确认合并请求后，攻击者身份才能登录该账号' do
    code = seed_provider_account('facebook', 'fb-evil-2',
                                 email: 'victim@example.com')
    complete_oauth_flow('facebook', code)
    mr = MergeRequest.last

    # 邮件链接确认（无需登录会话）
    token = mr.signed_id
    assert_difference -> { Identity.count } => 1 do
      get "/merge_requests/#{mr.id}/confirm", params: { token: token }
    end
    assert_equal 'confirmed', mr.reload.status
    identity = Identity.find_by(provider: 'facebook', provider_uid: 'fb-evil-2')
    assert_equal @victim.id, identity.user_id

    # 此后该身份登录直接进入受害者账号
    complete_oauth_flow('facebook', seed_provider_account('facebook', 'fb-evil-2',
                                                          email: 'victim@example.com'))
    assert_equal @victim.id, session[:user_id]
  end

  test '受害者拒绝后，身份保持未绑定，再次登录只会重新生成 pending 请求' do
    code = seed_provider_account('facebook', 'fb-evil-3',
                                 email: 'victim@example.com')
    complete_oauth_flow('facebook', code)
    mr = MergeRequest.last

    get "/merge_requests/#{mr.id}/reject", params: { token: mr.signed_id }
    assert_equal 'rejected', mr.reload.status
    assert_nil Identity.find_by(provider: 'facebook', provider_uid: 'fb-evil-3')

    complete_oauth_flow('facebook', seed_provider_account('facebook', 'fb-evil-3',
                                                          email: 'victim@example.com'))
    assert_nil session[:user_id]
    assert MergeRequest.last.status == 'pending'
  end

  test 'Google 明确返回 email_verified=false 时，同样只能走人工确认' do
    code = seed_provider_account('google', 'g-spoof-1',
                                 email: 'victim@example.com', email_verified: false)
    complete_oauth_flow('google', code)
    assert_nil session[:user_id]
    mr = MergeRequest.last
    assert_equal 'unverified', mr.email_verification
    assert_equal @victim.id, mr.target_user_id
  end

  test 'Google 返回已验证邮箱且站内无同邮箱账号，直接注册新账号' do
    code = seed_provider_account('google', 'g-new-1',
                                 email: 'brand-new@example.com',
                                 email_verified: true, name: 'New')
    assert_difference -> { User.count } => 1 do
      complete_oauth_flow('google', code)
    end
    user = User.find_by_normalized_email('brand-new@example.com')
    assert_equal user.id, session[:user_id]
    assert user.email_verified
    assert_equal 'verified', user.identities.last.email_verification
  end

  test '即使 Google 邮箱已验证，撞上站内已有账号仍需持有人确认（不自动合并）' do
    code = seed_provider_account('google', 'g-collide-1',
                                 email: 'victim@example.com', email_verified: true)
    complete_oauth_flow('google', code)
    assert_nil session[:user_id]
    assert_equal 'pending', MergeRequest.last.status
    assert_equal 'verified', MergeRequest.last.email_verification
  end

  test '被隔离的历史身份登录被拒绝' do
    identity = Identity.create!(user: @victim, provider: 'facebook',
                                provider_uid: 'fb-old', provider_email: 'victim@example.com',
                                email_verification: 'unknown', status: 'quarantined',
                                quarantine_reason: 'legacy-audit test')
    code = seed_provider_account('facebook', 'fb-old', email: 'victim@example.com')
    complete_oauth_flow('facebook', code)
    assert_nil session[:user_id]
    assert_redirected_to root_path
    assert SecurityEvent.exists?(event_type: 'oauth_login_blocked_quarantined',
                                 identity_id: identity.id)
  end

  test 'state 参数被篡改时回调被拒绝，不产生任何账号变化' do
    seed_provider_account('facebook', 'fb-x', email: 'x@example.com')
    get '/auth/facebook'
    code = MockOAuthRegistry.instance.issue_code('facebook', 'fb-x')
    assert_no_difference ['User.count', 'Identity.count', 'MergeRequest.count'] do
      get '/auth/facebook/callback', params: { code: code, state: 'forged-state' }
    end
    assert_nil session[:user_id]
    follow_redirect!
    assert_match(/授权状态校验失败/, response.body)
  end

  test '不支持的 provider 直接拒绝' do
    get '/auth/evil_provider'
    assert_redirected_to root_path
  end
end
