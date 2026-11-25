class MergeNotifierMailer < ApplicationMailer
  def merge_request_email(merge_request)
    @merge_request = merge_request
    @user = merge_request.target_user
    @token = merge_request.signed_id
    @confirm_url = merge_request_confirm_url(
      id: merge_request.id, token: @token, host: mailer_host
    )
    @reject_url = merge_request_reject_url(
      id: merge_request.id, token: @token, host: mailer_host
    )
    subject = if merge_request.provider_email_verified?
                "[安全通知] 第三方登录合并请求（对方邮箱已通过平台验证）"
              else
                "[安全警告] 第三方登录合并请求（对方邮箱未经平台验证，可能是冒名登录）"
              end
    mail(to: @user.email, subject: subject)
  end

  private

  def mailer_host
    ActionMailer::Base.default_url_options[:host] || 'localhost'
  end
end
