Rails.application.routes.draw do
  root 'home#index'

  get  '/login',  to: 'sessions#new'
  post '/login',  to: 'sessions#create'
  post '/logout', to: 'sessions#destroy'

  # 发起第三方授权；mode: login（默认）或 link（已登录用户绑定新身份）
  get  '/auth/:provider',          to: 'oauth#start', as: :oauth_start
  get  '/auth/:provider/callback', to: 'oauth#callback', as: :oauth_callback
  get  '/auth/:provider/failure',  to: 'oauth#failure'

  resource :account, only: :show, controller: 'accounts' do
    post   'identities/:provider', to: 'identities#create'
    post   'merge_requests/:id/confirm', to: 'merge_requests#confirm', as: :confirm_merge_request
    post   'merge_requests/:id/reject',  to: 'merge_requests#reject',  as: :reject_merge_request
    post   :password, to: 'accounts#update_password', as: :password
  end
  delete '/account/identities/:id', to: 'identities#destroy', as: :account_identity

  # 邮件链接：路径含请求 id，签名 token 放 query；无需登录即可决定
  get '/merge_requests/:id/confirm', to: 'merge_requests#confirm_by_token', as: :merge_request_confirm
  get '/merge_requests/:id/reject',  to: 'merge_requests#reject_by_token',  as: :merge_request_reject

  # 仅 development/test：模拟第三方授权服务器
  if Rails.env.development? || Rails.env.test?
    get  '/mock/:provider/authorize', to: 'mock_oauth#authorize'
    post '/mock/:provider/token',     to: 'mock_oauth#token'
    get  '/mock/:provider/userinfo',  to: 'mock_oauth#userinfo'
    get  '/mock/:provider/emails',    to: 'mock_oauth#emails'
    get  '/mock/:provider/jwks',      to: 'mock_oauth#jwks'
  end
end
