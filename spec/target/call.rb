#!/usr/bin/env ruby
# vim: set expandtab ts=2 sw=2 nowrap ft=ruby ff=unix : */

puts Process.pid

def method1(*args)
  Module1::method2(*args)
end

module Module1
  def self.method2(*args)
    Class1::method3(*args)
  end

  class Class1
    def self.method3(*args)
      eval('method4(*args)')
    end
  end
end

def method4(*args)
  begin
    raise
  rescue
    method5(*args)
  end
end

def method5(*args)
  begin
    raise
  rescue
  ensure
    method6(*args)
  end
end

def method6(*args)
  method7(*args) do |*args|
    p args
    sleep(100)
  end
end

def method7(*args)
  yield *args
end

# TODO: test Struct, Bignum, File, Data, Match, Complex, Rational
method1(
  nil,
  true,
  false,
  :symbol,
  1,
  Module1::Class1.new,
  Module1::Class1,
  Module1,
  1.0,
  'string',
  /regex/,
  ['array'],
  { :hash => :value },
)
