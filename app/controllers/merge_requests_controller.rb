class MergeRequestsController < ApplicationController
  # 邮件链接动作不需要登录（签名 token 本身即授权）；账号页动作才要求登录
  before_action :require_login, only: %i[confirm reject]

  # 已登录持有人在账号页确认
  def confirm
    request = current_user.merge_requests.find(params[:id])
    decide(request, :confirm!)
  end

  def reject
    request = current_user.merge_requests.find(params[:id])
    decide(request, :reject!)
  end

  # 邮件链接：签名 token 验证通过即可，无需会话
  def confirm_by_token
    request = MergeRequest.verified_by_signed_id(params[:token] || token_from_params)
    decide(request, :confirm!, require_owner: false)
  end

  def reject_by_token
    request = MergeRequest.verified_by_signed_id(params[:token] || token_from_params)
    decide(request, :reject!, require_owner: false)
  end

  private

  # 路由里 :id 是 merge_request 的真实 id；token 放在 query 参数
  def token_from_params
    params[:token].to_s
  end

  def decide(request, action, require_owner: true)
    if request.nil?
      flash[:alert] = '合并请求不存在、已处理或链接已过期'
      redirect_to(root_path) and return
    end
    if require_owner && request.target_user_id != current_user&.id
      flash[:alert] = '无权操作该请求'
      redirect_to(root_path) and return
    end
    if request.status != 'pending'
      flash[:alert] = '该请求已处理，无需重复操作'
      redirect_to(require_owner ? account_path : root_path) and return
    end

    request.public_send(action, note: params[:note])
    SecurityEvent.log!(action == :confirm! ? 'merge_request_confirmed' : 'merge_request_rejected',
                       user: request.target_user, merge_request: request,
                       provider: request.provider)
    if action == :confirm!
      flash[:notice] = '已确认合并，对方现在可以用该第三方账号登录此账号'
    else
      flash[:notice] = '已拒绝该合并请求，第三方身份未与你的账号关联'
    end
    redirect_to logged_in? ? account_path : login_path
  end
end
