# 开发环境的可视化 mock 授权页：选择一个预置账号后跳回 callback。
# 测试环境直接用 MockOAuthTransport + 手工构造回调 URL，不经过这里。
class MockOAuthController < ApplicationController
  skip_forgery_protection

  def authorize
    @provider = params[:provider]
    @accounts = MockOAuthRegistry.instance.accounts[@provider].keys
    render layout: false
  end

  def token
    render plain: 'use MockOAuthTransport in-process', status: :not_found
  end

  def userinfo
    render plain: 'use MockOAuthTransport in-process', status: :not_found
  end

  def emails
    render plain: 'use MockOAuthTransport in-process', status: :not_found
  end

  def jwks
    render json: { keys: [MockOAuthRegistry.jwk] }
  end
end
