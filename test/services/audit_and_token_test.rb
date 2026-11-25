require 'test_helper'

class LegacyMergeAuditTest < ActiveSupport::TestCase
  setup do
    @victim = User.create!(email: 'victim@e.com', email_verified: true,
                           password_digest: BCrypt::Password.create('password123'))
    @high = Identity.create!(user: @victim, provider: 'facebook', provider_uid: 'fb1',
                             provider_email: 'victim@e.com', email_verification: 'unknown',
                             linked_at: 1.day.ago)
    @low = Identity.create!(user: @victim, provider: 'google', provider_uid: 'g1',
                            provider_email: 'victim@e.com', email_verification: 'verified',
                            linked_at: 1.day.ago)
    @solo = User.create!(email: 'solo@e.com', email_verified: false)
    @medium = Identity.create!(user: @solo, provider: 'linkedin', provider_uid: 'li1',
                               provider_email: 'other@e.com', email_verification: 'unknown',
                               linked_at: 1.day.ago)
  end

  test 'audit 模式只出报告，不改数据' do
    findings = Audit::LegacyMergeAudit.run(mode: 'audit')
    risks = findings.map { |f| [f.identity.id, f.risk] }.to_h
    assert_equal 'high', risks[@high.id]
    assert_equal 'low', risks[@low.id]
    assert_equal 'medium', risks[@medium.id]
    assert_equal 'active', @high.reload.status
    assert SecurityEvent.exists?(event_type: 'legacy_audit_finding')
  end

  test 'quarantine 模式隔离 high 身份并生成 pending 合并请求' do
    Audit::LegacyMergeAudit.run(mode: 'quarantine')
    assert_equal 'quarantined', @high.reload.status
    assert_match(/legacy-audit/, @high.quarantine_reason)
    assert_equal 'active', @low.reload.status
    assert_equal 'active', @medium.reload.status # medium 不隔离
    mr = MergeRequest.find_by(provider: 'facebook', provider_uid: 'fb1')
    assert_equal 'pending', mr.status
    assert_equal @victim.id, mr.target_user_id
  end

  test '重复 quarantine 幂等，不产生重复 MergeRequest' do
    Audit::LegacyMergeAudit.run(mode: 'quarantine')
    assert_no_difference 'MergeRequest.count' do
      Audit::LegacyMergeAudit.run(mode: 'quarantine')
    end
  end
end

class MergeRequestTokenTest < ActiveSupport::TestCase
  setup do
    @user = User.create!(email: 'v@e.com', email_verified: true)
    @mr = MergeRequest.create!(target_user: @user, provider: 'facebook',
                               provider_uid: 'fb1', provider_email: 'v@e.com',
                               email_verification: 'unknown')
  end

  test '合法 token 能找回 pending 请求' do
    found = MergeRequest.verified_by_signed_id(@mr.signed_id)
    assert_equal @mr.id, found.id
  end

  test '伪造 token 被拒' do
    assert_nil MergeRequest.verified_by_signed_id('not-a-real-token')
  end

  test '已处理的请求 token 失效' do
    @mr.confirm!
    assert_nil MergeRequest.verified_by_signed_id(@mr.signed_id)
  end

  test '过期 token 被拒' do
    # 显式构造一个 expires_at 已过去的 token，不依赖时间旅行
    verifier = Rails.application.message_verifier(:merge_request)
    expired = verifier.generate(
      { id: @mr.id, purpose: MergeRequest::TOKEN_PURPOSE,
        expires_at: 1.minute.ago.to_i },
      expires_in: 1.minute
    )
    assert_nil MergeRequest.verified_by_signed_id(expired)
  end

  test 'confirm! 会建立绑定到目标用户的 active identity' do
    @mr.confirm!
    identity = Identity.find_by(provider: 'facebook', provider_uid: 'fb1')
    assert_equal @user.id, identity.user_id
    assert_equal 'active', identity.status
  end
end

class JwtVerifierTest < ActiveSupport::TestCase
  test '合法 RS256 token 通过签名与 claim 校验' do
    claims = { sub: 'u1', iss: 'https://appleid.apple.com',
               aud: 'mock-apple-client-id', email: 'a@e.com',
               email_verified: 'true' }
    token = MockOAuthRegistry.signed_jwt(claims)
    decoded = OAuth::JwtVerifier.verify(
      token, jwks_url: '/mock/apple/jwks',
      issuer: 'https://appleid.apple.com',
      audience: 'mock-apple-client-id',
      transport: MockOAuthTransport.new('apple')
    )
    assert_equal 'u1', decoded['sub']
  end

  test '签名与内容不符时校验失败' do
    token = MockOAuthRegistry.signed_jwt(
      sub: 'u1', iss: 'https://appleid.apple.com', aud: 'mock-apple-client-id'
    )
    header, _payload, sig = token.split('.')
    # 用一个内容不同但结构合法的 payload 替换原 payload，签名输入必然变化。
    # 不能只改 base64 末字符——填充位可能让解码结果恰好不变，造成偶发误判。
    tampered_payload = OAuth::JwtVerifier.base64url_encode(
      JSON.generate(sub: 'attacker', iss: 'https://appleid.apple.com',
                    aud: 'mock-apple-client-id')
    )
    tampered = "#{header}.#{tampered_payload}.#{sig}"
    assert_raises(OAuth::JwtVerifier::ClaimError) do
      OAuth::JwtVerifier.verify(
        tampered, jwks_url: '/mock/apple/jwks',
        issuer: 'https://appleid.apple.com', audience: 'mock-apple-client-id',
        transport: MockOAuthTransport.new('apple')
      )
    end
  end

  test 'aud/iss 不匹配被拒' do
    token = MockOAuthRegistry.signed_jwt(
      sub: 'u1', iss: 'https://evil.example', aud: 'wrong'
    )
    assert_raises(OAuth::JwtVerifier::ClaimError) do
      OAuth::JwtVerifier.verify(
        token, jwks_url: '/mock/apple/jwks',
        issuer: 'https://appleid.apple.com', audience: 'mock-apple-client-id',
        transport: MockOAuthTransport.new('apple')
      )
    end
  end
end
