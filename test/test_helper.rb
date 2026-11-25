ENV['RAILS_ENV'] ||= 'test'
require_relative '../config/environment'
require 'rails/test_help'

class ActiveSupport::TestCase
  setup do
    # 顺序受外键约束：先删引用方，再删被引用方
    SecurityEvent.delete_all
    MergeRequest.delete_all
    Identity.delete_all
    User.delete_all
    MockOAuthRegistry.instance.reset!
    ActionMailer::Base.deliveries.clear
  end

  # 在 mock provider 中预置一个第三方账号，并返回可用于回调的授权码
  def seed_provider_account(provider, uid, attrs = {})
    MockOAuthRegistry.instance.seed(provider, uid, attrs.merge(uid: uid))
    MockOAuthRegistry.instance.issue_code(provider, uid)
  end

  # 完整模拟一次第三方回调：先发 start 建立 state 会话，再打 callback
  def complete_oauth_flow(provider, code, mode: 'login')
    get "/auth/#{provider}"
    state = session_state
    get "/auth/#{provider}/callback", params: { code: code, state: state }
  end

  def session_state
    # rack-test 保留 cookie，state 存在服务端 session 里；
    # start 重定向到 mock 授权页，state 也出现在 Location 上
    location = response.location
    Rack::Utils.parse_query(URI(location).query)['state']
  end

  def login_as(user)
    post '/login', params: { email: user.email, password: @password_for[user] }
  end

  def seed_password(user, password)
    @password_for ||= {}
    @password_for[user] = password
    user.update!(password_digest: BCrypt::Password.create(password))
  end
end

class ActionDispatch::IntegrationTest
  # 与 ActiveSupport::TestCase 共享 helper
end
