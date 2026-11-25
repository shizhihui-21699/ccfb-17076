Rails.application.configure do
  config.cache_classes = true
  config.eager_load = true
  config.consider_all_requests_local = false
  config.action_controller.perform_caching = true
  config.active_support.deprecation = :notify
  config.action_mailer.default_url_options = { host: ENV.fetch('APP_HOST', 'example.com') }
  config.log_level = :info
end
