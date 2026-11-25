Rails.application.configure do
  config.cache_classes = false
  config.eager_load = false
  config.consider_all_requests_local = true
  config.active_support.deprecation = :log
  config.action_controller.perform_caching = false
  config.active_record.migration_error = :page_load
  config.action_mailer.perform_caching = false
  config.action_mailer.raise_delivery_errors = false
  config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }
  config.file_watcher = ActiveSupport::FileUpdateChecker
end
