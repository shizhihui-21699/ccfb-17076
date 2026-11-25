class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  helper_method :current_user, :logged_in?

  private

  def current_user
    @current_user ||= User.find_by(id: session[:user_id]) if session[:user_id]
  end

  def logged_in?
    current_user.present?
  end

  def require_login
    return if logged_in?
    flash[:alert] = '请先登录后再操作'
    redirect_to login_path
  end

  def login!(user)
    # 防 session fixation：登录后换 session id
    reset_session
    session[:user_id] = user.id
  end
end
