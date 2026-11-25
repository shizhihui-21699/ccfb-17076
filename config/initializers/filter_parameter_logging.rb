# 过滤敏感参数，避免 client_secret 等进入日志
Rails.application.config.filter_parameters += %i[
  password token access_token refresh_token id_token code client_secret secret
]
