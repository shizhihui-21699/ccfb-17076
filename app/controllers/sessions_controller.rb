class SessionsController < ApplicationController
  def new
    redirect_to account_path if logged_in?
  end

  def create
    user = User.find_by_normalized_email(params[:email])
    if user&.authenticate(params[:password])
      login!(user)
      flash[:notice] = '登录成功'
      redirect_to account_path
    else
      SecurityEvent.log!('login_failed', ip_address: request.remote_ip,
                                          detail: "email=#{params[:email]}")
      flash.now[:alert] = '邮箱或密码错误'
      render :new, status: :unauthorized
    end
  end

  def destroy
    reset_session
    flash[:notice] = '已退出登录'
    redirect_to root_path
  end
end
