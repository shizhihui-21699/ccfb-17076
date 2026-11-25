Rails.application.configure do
  config.cache_classes = true
  config.eager_load = false
  config.consider_all_requests_local = true
  config.action_controller.perform_caching = false
  config.action_dispatch.show_exceptions = false
  config.action_controller.allow_forgery_protection = false # 集成测试默认关闭；state 参数单独测试 CSRF
  config.active_support.deprecation = :stderr
  config.action_mailer.delivery_method = :test
  config.action_mailer.default_url_options = { host: 'test.local' }
end
