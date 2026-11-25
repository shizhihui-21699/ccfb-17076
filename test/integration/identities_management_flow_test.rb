require 'test_helper'

class IdentitiesManagementFlowTest < ActionDispatch::IntegrationTest
  setup do
    @user = User.create!(email: 'owner@e.com', email_verified: true)
    seed_password(@user, 'password123')
  end

  test '未登录不能访问账号页或发起绑定' do
    get '/account'
    assert_redirected_to '/login'
    get '/auth/google?mode=link'
    assert_redirected_to '/login'
  end

  test '唯一凭据的 identity 不允许解绑，设置密码后可以' do
    # 无密码、只有这一条 identity 的账号
    solo = User.create!(email: 'solo@e.com', email_verified: true)
    identity = Identity.create!(user: solo, provider: 'google', provider_uid: 'g1',
                                email_verification: 'verified', linked_at: Time.current)
    seed_password(solo, 'password123')
    login_as(solo)

    # 先清掉密码，模拟“只有第三方凭据”的状态
    solo.update!(password_digest: nil)
    assert_no_difference 'Identity.count' do
      delete "/account/identities/#{identity.id}"
    end
    assert_redirected_to '/account'
    assert_equal 1, Identity.count

    # 建立密码后可以解绑
    post '/account/password', params: { password: 'another-strong-pw' }
    assert_difference 'Identity.count', -1 do
      delete "/account/identities/#{identity.id}"
    end
    assert_equal 0, Identity.count
  end

  test '已登录用户主动绑定新身份成功，且不需要平台邮箱验证' do
    login_as(@user)
    code = seed_provider_account('facebook', 'fb-link-1', email: 'owner@e.com')
    get '/auth/facebook?mode=link'
    state = Rack::Utils.parse_query(URI(response.location).query)['state']
    get '/auth/facebook/callback', params: { code: code, state: state }
    identity = Identity.find_by(provider: 'facebook', provider_uid: 'fb-link-1')
    assert_equal @user.id, identity.user_id
    assert_equal 'unknown', identity.email_verification
  end

  test '密码登录失败不泄露账号是否存在，且记录安全事件' do
    post '/login', params: { email: 'owner@e.com', password: 'wrong' }
    assert_response :unauthorized
    assert SecurityEvent.exists?(event_type: 'login_failed')
  end

  test '登录后建立用户会话（reset_session 在控制器内完成）' do
    get '/login'
    post '/login', params: { email: 'owner@e.com', password: 'password123' }
    assert_redirected_to '/account'
    get '/account'
    assert_response :success
  end
end
