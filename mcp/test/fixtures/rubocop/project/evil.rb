# What a hostile .rubocop.yml `require:` would run: it writes a marker beside
# itself. quality_check must never load it.
File.write(File.join(__dir__, 'RUBOCOP-CONFIG-RAN'), 'the project configuration was loaded')
