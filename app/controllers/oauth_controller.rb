class OAuthController < ApplicationController
  skip_forgery_protection only: :callback # 回调由 state 参数承担 CSRF 防护

  before_action :validate_provider

  def start
    mode = params[:mode] == 'link' ? 'link' : 'login'
    if mode == 'link' && !logged_in?
      flash[:alert] = '请先登录后再绑定第三方账号'
      redirect_to login_path and return
    end

    handler = OAuth::AuthorizationHandler.new(@provider)
    state = OAuth::AuthorizationHandler.start_session!(session, mode: mode)
    redirect_to handler.authorize_url(
      state: state, mode: mode,
      redirect_uri: oauth_callback_url(@provider)
    ), allow_other_host: true
  end

  def callback
    if params[:error].present?
      flash[:alert] = "第三方授权失败：#{params[:error_description] || params[:error]}"
      redirect_to root_path and return
    end

    OAuth::AuthorizationHandler.consume_state!(session, params[:state])
    handler = OAuth::AuthorizationHandler.new(@provider, transport: mock_or_real_transport)
    profile = handler.fetch_profile(code: params[:code],
                                    redirect_uri: oauth_callback_url(@provider))
    mode = session.delete(OAuth::AuthorizationHandler::MODE_SESSION_KEY) { 'login' }

    if mode == 'link'
      handle_link(profile)
    else
      handle_login(profile)
    end
  rescue OAuth::AuthorizationHandler::StateMismatch
    flash[:alert] = '授权状态校验失败，请重试'
    redirect_to root_path
  rescue OAuth::ProviderError, OAuth::TransportError => e
    Rails.logger.warn("[oauth] #{@provider} failed: #{e.message}")
    flash[:alert] = '第三方登录暂时不可用，请稍后重试'
    redirect_to root_path
  end

  def failure
    flash[:alert] = "第三方授权失败：#{params[:message] || 'unknown error'}"
    redirect_to root_path
  end

  private

  def validate_provider
    @provider = params[:provider].to_s
    unless OAuth::ProviderRegistry.known?(@provider)
      flash[:alert] = '不支持的登录平台'
      redirect_to root_path
    end
  end

  def handle_login(profile)
    result = OAuth::LoginService.call(profile: profile,
                                      ip_address: request.remote_ip)
    case result.outcome
    when :login, :registered
      login!(result.user)
      flash[:notice] = result.outcome == :registered ? '已通过第三方平台创建账号' : '登录成功'
      redirect_to account_path
    when :merge_pending
      # 统一文案，不透露邮箱是否已被注册（防账号枚举）
      flash[:notice] = '登录请求已提交。若该邮箱已有站内账号，账号持有人会收到确认邮件，' \
                       '确认后第三方身份才会与账号合并。'
      redirect_to root_path
    when :blocked
      flash[:alert] = '该第三方登录身份已被安全隔离，请联系客服处理'
      redirect_to root_path
    end
  end

  def handle_link(profile)
    unless logged_in?
      flash[:alert] = '会话已过期，请重新登录后再绑定'
      redirect_to login_path and return
    end
    result = OAuth::LinkService.call(current_user, profile)
    if result.success?
      flash[:notice] = '第三方账号绑定成功'
    else
      flash[:alert] = result.error
    end
    redirect_to account_path
  end

  # 开发/测试环境把请求导向内置 mock 服务器；生产环境走真实 HTTPS
  def mock_or_real_transport
    if Rails.env.development? || Rails.env.test?
      MockOAuthTransport.new(@provider, request)
    else
      OAuth::HttpTransport
    end
  end
end
