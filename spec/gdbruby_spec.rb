require 'spec_helper'
require 'tempfile'
require 'rbconfig'

RUBY = RbConfig.ruby
GDBRUBY = File.join(File.dirname(__FILE__), '..', 'bin', 'gdbruby.rb')
TARGET = File.expand_path(File.join(File.dirname(__FILE__), 'target', 'call.rb'))

describe 'gdbruby' do
  describe 'execute' do
    RESULT = <<EOF
[13] sleep() <- #{TARGET}:42
[12] Module1::Class1#block in method6() <- #{TARGET}:42
[11] Module1::Class1#method7() <- #{TARGET}:47
[10] Module1::Class1#method6() <- #{TARGET}:40
[9] Module1::Class1#method5() <- #{TARGET}:35
[8] Module1::Class1#rescue in method4() <- #{TARGET}:26
[7] Module1::Class1#method4() <- #{TARGET}:23
[6] Module1::Class1#method3() <- (eval):1
[5] eval() <- #{TARGET}:17
[4] Module1::Class1#method3() <- #{TARGET}:17
[3] method2() <- #{TARGET}:12
[2] method1() <- #{TARGET}:7
[1] <main>() <- #{TARGET}:51
EOF

    before(:all) do
      @target_pid = Kernel.spawn("#{RUBY} #{TARGET}", :pgroup => true, :out => '/dev/null', :err => '/dev/null')
    end

    context 'OS' do
      it 'should be linux' do
        host_os = RbConfig::CONFIG['host_os']
        expect(host_os.match(/\Alinux/)).to_not be_nil
      end
    end

    context 'With live process' do
      before(:all) do
        @output = `#{RUBY} #{GDBRUBY} #{@target_pid}`
      end

      it 'should work' do
        @output =~ /ruby_backtrace:\n(.+)\z/m
        ruby_backtrace = $1
        expect(ruby_backtrace).to eq(RESULT)
      end
    end

    gcore_path = `which gcore`.chomp!
    if File.executable?(gcore_path)
      context 'With core file' do
        before(:all) do
          @core_path = Tempfile.new('core')
#          puts "target_pid: #{@target_pid}"
          system('gcore', '-o', @core_path.path, @target_pid.to_s)
          @output = `#{RUBY} #{GDBRUBY} #{@core_path.path}.#{@target_pid} #{RUBY}`
        end

        it 'should work' do
          @output =~ /ruby_backtrace:\n(.+)\z/m
          ruby_backtrace = $1
          expect(ruby_backtrace).to eq(RESULT)
        end

        after(:all) do
          @core_path.close!
        end
      end
    end

    after(:all) do
      Process.kill('KILL', @target_pid)
    end
  end
end
