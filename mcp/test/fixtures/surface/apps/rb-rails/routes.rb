# frozen_string_literal: true

Rails.application.routes.draw do
  # Bare form: no options hash.
  get '/rails/orders'

  # Idiomatic form with a trailing options hash.
  get '/rails/orders/:id', to: 'orders#show'
  post '/rails/orders', to: 'orders#create'
  delete '/rails/orders/:id', to: 'orders#destroy'

  # Not routes: neither takes a string path.
  resources :invoices, only: %i[index show]
  root to: 'home#index'
end
