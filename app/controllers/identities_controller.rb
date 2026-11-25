class IdentitiesController < ApplicationController
  before_action :require_login

  def create
    # 实际绑定走 OAuth 流程（OauthController#start mode=link），这里只是语义化入口
    redirect_to oauth_start_path(params[:provider], mode: 'link'), allow_other_host: true
  end

  def destroy
    identity = current_user.identities.find(params[:id])
    unless current_user.can_remove_identity?(identity)
      flash[:alert] = '这是该账号唯一的登录方式，请先设置密码后再解绑'
      redirect_to account_path and return
    end
    identity.destroy!
    SecurityEvent.log!('identity_unlinked', user: current_user,
                       provider: identity.provider,
                       detail: "#{identity.provider}:#{identity.provider_uid}")
    flash[:notice] = '已解绑该第三方账号'
    redirect_to account_path
  end
end
