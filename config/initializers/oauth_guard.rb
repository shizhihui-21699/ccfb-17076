# 合并确认 token 的有效期
Rails.application.config.x.merge_token_ttl = 24.hours
# 同一身份对同一账号最多保留的 pending 请求数（去重之外的兜底）
Rails.application.config.x.max_pending_merge_requests = 5
