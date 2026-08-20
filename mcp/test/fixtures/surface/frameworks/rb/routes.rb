require 'json'
require_relative 'support/helpers'
require 'sinatra/base'
load 'legacy.rb'

Rails.application.routes.draw do
  # B01 control
  get '/rails/orders', to: 'orders#index'
  # B02 bare symbol-style path (no leading slash, no quotes)
  get 'rails/orders/:id', to: 'orders#show'
  # B03 resources — THE idiomatic Rails form, 7 routes in one line
  resources :orders
  resources :users, only: [:index, :show]
  # B04 namespace + scoped verbs
  namespace :api do
    get '/ping', to: 'health#ping'
  end
  # B05 root
  root 'home#index'
  # B06 match with via
  match '/either', to: 'x#y', via: [:get, :post]
end
