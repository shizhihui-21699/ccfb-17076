module OAuth
  # 第三方返回的统一用户资料。email_verification 三态：
  #   verified   —— provider 明确表示邮箱已验证（且验证方式可信）
  #   unverified —— provider 明确表示未验证
  #   unknown    —— provider 不提供验证状态；安全上一律按“未验证”对待
  class ProviderProfile
    attr_reader :provider, :uid, :email, :email_verification, :name, :raw

    def initialize(provider:, uid:, email:, email_verification:, name: nil, raw: {})
      raise ArgumentError, 'uid is required' if uid.blank?
      raise ArgumentError, "bad verification state: #{email_verification}" unless
        %w[verified unverified unknown].include?(email_verification)

      @provider = provider
      @uid = uid.to_s
      @email = email.presence&.strip&.downcase
      @email_verification = email_verification
      @name = name
      @raw = raw
    end

    def provider_email_verified?
      email_verification == 'verified'
    end

    def to_h
      { provider: provider, uid: uid, email: email,
        email_verification: email_verification, name: name }
    end
  end
end
