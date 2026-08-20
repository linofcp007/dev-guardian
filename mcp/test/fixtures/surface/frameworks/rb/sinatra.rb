require 'sinatra'

# B10 Sinatra block form — the canonical Sinatra route
get '/sin/health' do
  'ok'
end

post '/sin/items' do
  status 201
end

# B11 with a regexp path
get %r{/sin/items/(\d+)} do
  params['captures']
end
