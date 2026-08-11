# frozen_string_literal: true

# Bait for the Rails rule: `$METHOD $PATH` is any one-argument Ruby call, and
# `get` / `delete` are ordinary cache method names. These calls have an explicit
# receiver, which is what keeps them out of the route inventory.
class CacheWarmer
  def call
    Rails.cache.delete 'orders/index'
    Rails.cache.write 'orders/index', build
    store.get 'orders/index'
  end

  private

  def build
    { warmed: true }
  end

  def store
    Rails.cache
  end
end
