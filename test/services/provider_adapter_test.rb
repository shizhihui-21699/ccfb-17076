require 'test_helper'

# 各家 provider 适配器对“邮箱验证状态”的归一化测试
class ProviderAdapterTest < ActiveSupport::TestCase
  def profile_via(provider, code_attrs = {})
    uid = "u-#{SecureRandom.hex(4)}"
    seed_provider_account(provider, uid, code_attrs)
    transport = MockOAuthTransport.new(provider)
    token = transport.post_form("/mock/#{provider}/token",
                                form: { code: MockOAuthRegistry.instance.issue_code(provider, uid) }).json
    OAuth::ProviderRegistry.adapter_for(provider, transport: transport)
                          .fetch_profile(access_token: token['access_token'],
                                         id_token: token['id_token'])
  end

  test 'Google: email_verified=true 归为 verified' do
    p = profile_via('google', email: 'a@example.com', email_verified: true)
    assert_equal 'verified', p.email_verification
    assert_equal 'a@example.com', p.email
  end

  test 'Google: 字符串 "true" 也归为 verified；false 归为 unverified' do
    assert_equal 'verified', profile_via('google', email: 'a@e.com', email_verified: 'true').email_verification
    assert_equal 'unverified', profile_via('google', email: 'b@e.com', email_verified: false).email_verification
  end

  test 'Google: 缺少标记时归为 unknown，绝不默认 verified' do
    p = profile_via('google', email: 'c@e.com')
    assert_equal 'unknown', p.email_verification
  end

  test 'Apple: 字符串型 email_verified 正确归一' do
    assert_equal 'verified', profile_via('apple', email: 'a@e.com', email_verified: 'true').email_verification
    assert_equal 'unverified', profile_via('apple', email: 'b@e.com', email_verified: 'false').email_verification
  end

  test 'GitHub: 只承认 verified+primary 主邮箱' do
    p = profile_via('github', name: 'octo', email: 'octo@example.com',
                    emails: [{ email: 'octo@example.com', primary: true, verified: true }])
    assert_equal 'verified', p.email_verification
    assert_equal 'octo@example.com', p.email

    p2 = profile_via('github', name: 'octo2', email: 'x@example.com',
                     emails: [{ email: 'x@example.com', primary: true, verified: false }])
    refute_equal 'verified', p2.email_verification
  end

  test 'Facebook / Microsoft / LinkedIn / Twitter: 无验证信号，一律 unknown' do
    %w[facebook linkedin].each do |provider|
      assert_equal 'unknown', profile_via(provider, email: 'a@e.com').email_verification
    end
    assert_equal 'unknown', profile_via('microsoft', email: 'a@e.com').email_verification
    twitter = profile_via('twitter', name: 'n', login: 'u')
    assert_nil twitter.email
    assert_equal 'unknown', twitter.email_verification
  end

  test 'ProviderRegistry 拒绝未知 provider' do
    assert_raises(OAuth::ProviderRegistry::UnknownProvider) do
      OAuth::ProviderRegistry.adapter_for('nonexistent')
    end
  end
end
