class HomeController < ApplicationController
  def index
    @providers = OAuth::ProviderRegistry.names
  end
end
