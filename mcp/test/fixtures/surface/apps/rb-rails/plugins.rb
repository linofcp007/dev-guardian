# frozen_string_literal: true

# Fixture for guardian-import-ruby: `require`, `require_relative` and `load`
# never bind a local name, so this file exists purely to be scanned, not to
# be a realistic plugin loader.

require 'json'
require_relative 'support/cache_helpers'
load 'legacy_tasks.rb'
