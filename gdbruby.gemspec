#! /usr/bin/env gem build
# encoding: utf-8

Gem::Specification.new do |gem|
  gem.name          = 'gdbruby'
  gem.version       = File.read(File.expand_path('VERSION', File.dirname(__FILE__))).chomp
  gem.authors       = ["Tasuku SUENAGA"]
  gem.email         = ["tasuku-s-github@titech.ac"]
  gem.homepage      = "https://github.com/gunyarakun/gdbruby"
  gem.summary       = "gdbperl for Ruby"
  gem.description   = gem.summary
  gem.licenses      = ["New BSD"]

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_development_dependency "rake"
  gem.add_development_dependency "rspec"
end
