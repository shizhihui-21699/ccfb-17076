class AccountsController < ApplicationController
  before_action :require_login

  def show
    @identities = current_user.identities.order(:provider)
    @merge_requests = current_user.merge_requests.order(created_at: :desc)
  end

  # 让只有第三方登录方式的账号也能建立密码凭据，从而安全解绑
  def update_password
    if params[:password].to_s.length < 8
      flash[:alert] = '密码至少 8 位'
    else
      current_user.update!(password_digest: BCrypt::Password.create(params[:password]))
      flash[:notice] = '密码已更新'
    end
    redirect_to account_path
  end
end
