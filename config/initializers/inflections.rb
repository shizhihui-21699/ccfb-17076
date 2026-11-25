# Be careful with inflections here; provider 名称等均为普通字符串，无需额外规则
ActiveSupport::Inflector.inflections(:en) do |inflect|
  inflect.acronym 'OAuth'
end
