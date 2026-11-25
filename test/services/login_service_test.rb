require 'test_helper'

class LoginServiceTest < ActiveSupport::TestCase
  def build_profile(provider:, uid:, email:, verification:, name: nil)
    OAuth::ProviderProfile.new(provider: provider, uid: uid, email: email,
                               email_verification: verification, name: name)
  end

  test '已绑定 active 身份直接登录' do
    user = User.create!(email: 'a@e.com', email_verified: true)
    Identity.create!(user: user, provider: 'google', provider_uid: 'u1',
                     email_verification: 'verified', linked_at: Time.current)
    result = OAuth::LoginService.call(
      profile: build_profile(provider: 'google', uid: 'u1', email: 'a@e.com',
                             verification: 'verified'))
    assert result.login?
    assert_equal user.id, result.user.id
  end

  test '同邮箱碰撞生成 MergeRequest 而非自动合并，且重复请求去重' do
    victim = User.create!(email: 'victim@e.com', email_verified: true)
    profile = build_profile(provider: 'facebook', uid: 'fb1',
                            email: 'victim@e.com', verification: 'unknown')

    r1 = OAuth::LoginService.call(profile: profile)
    assert r1.pending?
    assert_nil r1.user
    assert_equal victim.id, r1.merge_request.target_user_id

    assert_no_difference 'MergeRequest.count' do
      r2 = OAuth::LoginService.call(profile: profile)
      assert r2.pending?
      assert_equal r1.merge_request.id, r2.merge_request.id
    end
  end

  test '无邮箱 provider 用占位邮箱注册，不与任何真实邮箱碰撞' do
    result = OAuth::LoginService.call(
      profile: build_profile(provider: 'twitter', uid: 'tw1', email: nil,
                             verification: 'unknown', name: 'n'))
    assert result.registered?
    assert_match(/\.placeholder\.invalid\z/, result.user.email)
    refute result.user.email_verified
  end

  test '邮箱匹配大小写不敏感' do
    User.create!(email: 'mixed@example.com', email_verified: true)
    result = OAuth::LoginService.call(
      profile: build_profile(provider: 'facebook', uid: 'f1',
                             email: 'MIXED@EXAMPLE.COM', verification: 'unknown'))
    assert result.pending?
  end

  test 'LinkService 拒绝绑定已属于他人的身份' do
    owner = User.create!(email: 'owner@e.com', email_verified: true)
    other = User.create!(email: 'other@e.com', email_verified: true)
    Identity.create!(user: owner, provider: 'google', provider_uid: 'u9',
                     email_verification: 'verified', linked_at: Time.current)

    result = OAuth::LinkService.call(
      other, build_profile(provider: 'google', uid: 'u9', email: 'owner@e.com',
                           verification: 'verified'))
    refute result.success?
    assert_equal 1, owner.identities.count
  end

  test 'LinkService 允许本人重复绑定同一身份（幂等刷新）' do
    user = User.create!(email: 'u@e.com', email_verified: true)
    result = OAuth::LinkService.call(
      user, build_profile(provider: 'github', uid: 'g1', email: 'u@e.com',
                          verification: 'verified'))
    assert result.success?
    assert_no_difference 'Identity.count' do
      OAuth::LinkService.call(
        user, build_profile(provider: 'github', uid: 'g1', email: 'u@e.com',
                            verification: 'verified'))
    end
  end
end
