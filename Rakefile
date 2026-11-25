require_relative 'config/application'

Rails.application.load_tasks
Dir.glob(File.expand_path('lib/tasks/**/*.rake', __dir__)).each { |f| load(f) }
