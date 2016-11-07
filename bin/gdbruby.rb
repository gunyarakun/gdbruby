#!/usr/bin/env ruby
# vim: set expandtab ts=2 sw=2 nowrap ft=ruby ff=unix : */

# gdbruby.rb - shows the call trace of a running ruby process
#
# Ruby porting of gdbperl.pl.
# gdbperl.pl is made by ahiguchi.
# https://github.com/ahiguti/gdbperl
#
# Copyright (c) Tasuku SUENAGA a.k.a. gunyarakun
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   Neither the name of the author nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Usage: gdbruby.rb PROCESS_ID [ruby_EXECUTABLE] [OPTION=VALUE [...]]
#        gdbruby.rb CORE_FILE ruby_EXECUTABLE [OPTION=VALUE [...]]

require 'open3'

class GDBRubyConfig
  attr_reader :core_or_pid, :exe, :is_pid

  def initialize(argvs)
    @config_map = {}
    @argv = []

    argvs.each do |argv|
      if argv =~ /^(\w+)=(.+)$/
        @config_map[$1] = $2
      else
        @argv << argv
      end
    end

    parse_argv
  end

  def parse_argv
    @core_or_pid = @argv[0]

    unless @core_or_pid
      message =
        "Usage: #{$0} PROCESS_ID [ruby_EXECUTABLE] [OPTION=VALUE [...]]\n" +
        "Usage: #{$0} CORE_FILE ruby_EXECUTABLE [OPTION=VALUE [...]]\n"
      puts message
      exit 1
    end

    exe = @argv[1]

    @is_pid = (@core_or_pid =~ /^\d+$/)
    if @is_pid
      if exe.nil?
        begin
          if RUBY_PLATFORM =~ /linux/
            exe = File.readlink("/proc/#{@core_or_pid}/exe")
          end
        rescue
        end
      end

      if exe.nil?
        exe = `rbenv which ruby`
        exe = `which ruby` unless FileTest.exist?(exe)
        exe.chomp!
      end
    end

    raise "failed to detect ruby executable" unless exe
    @exe = exe
  end

  def [](key, default_value = nil)
    if @config_map.has_key?(key)
      return case default_value
      when TrueClass, FalseClass
        not (@config_map[key].empty? || @config_map[key] == '0')
      when Numeric
        @config_map[key].to_i
      else
        @config_map[key]
      end
    end
    default_value
  end
end

class GDB
  COMMAND_READ_BUFFER_SIZE = 1024
  attr_reader :exec_options

  def initialize(config)
    @config = config
    @exec_options = ['gdb', '-silent', '-nw', @config.exe, @config.core_or_pid]
  end

  def run
    @gdb_stdin, @gdb_stdout, @gdb_stderr = *Open3.popen3(*@exec_options)
    prepare
    begin
      yield
      detach
    ensure
      if @config.is_pid
        Process.kill('CONT', @config.core_or_pid.to_i)
      end
      @gdb_stdin.close
      @gdb_stdout.close
      @gdb_stderr.close
    end
  end

  def prepare
    cmd_exec('')
    cmd_exec('set pagination off')
  end

  def detach
    cmd_get_value("detach")
    cmd_get_value("quit")
  end

  def log_gdb(pre, message)
    return unless @config['verbose_gdb', false]
    message.each_line do |line|
      puts "#{pre}: #{line}"
    end
  end

  def cmd_get_pointer(cmd, type)
    response = cmd_exec(cmd)
    raise "Invalid pointer #{response}" unless response =~ /#{type} \*\) (0x[0-9a-f]+)/
    $1
  end

  def cmd_exec(cmd)
    log_gdb('C', cmd)
    if cmd
      send_cmd = cmd.empty? ? cmd : "#{cmd}\n"
      r = @gdb_stdin.syswrite(send_cmd)
      if r < send_cmd.length
        raise "failed to send: [#{cmd}]"
      end
    end

    responses = []
    while true
      # TODO: specify buffer size
      begin
        buf = @gdb_stdout.sysread(COMMAND_READ_BUFFER_SIZE)
      rescue
        break
      end
      responses << buf
      break if buf =~ /\(gdb\) $/
    end

    response = responses.join('')
    log_gdb('R', response)
    response
  end

  def cmd_get_value(cmd)
    response = cmd_exec(cmd)
    return '' unless response =~ /\A\$\d+ =\s+(.+)/

    value = $1
    if value =~ /0x\w+\s+\"(.+)\"/
      $1
    else
      value
    end
  end
end

class RubyInternal
  FL_USHIFT = 12
  FL_USER1 = 1 << (FL_USHIFT + 1)
  RSTRING_NOEMBED = FL_USER1

  VM_FRAME_MAGIC_CFUNC = 0x61
  VM_FRAME_MAGIC_MASK_BITS = 8
  VM_FRAME_MAGIC_MASK = ~(~0 << VM_FRAME_MAGIC_MASK_BITS)

  def initialize(gdb)
    @gdb = gdb
  end

  def ruby_vm_ifunc_p(pointer)
    # pointer is string like 0xaabbccdd
    @gdb.cmd_get_value("p (enum ruby_value_type)(((struct RBasic *)(#{pointer}))->flags & RUBY_T_MASK) == RUBY_T_NODE") != '0'
  end

  def ruby_vm_normal_iseq_p(pointer)
    @gdb.cmd_get_value("p #{pointer} && #{pointer} != 0") != '0' and not ruby_vm_ifunc_p(pointer)
  end

  def rb_vm_get_sourceline(cfp, iseq)
    if ruby_vm_normal_iseq_p(iseq)
      # calc_lineno()@vm_backtrace.c
      current_position = @gdb.cmd_get_value("p #{cfp}->pc - #{iseq}->iseq_encoded").to_i
      # rb_iseq_line_no()@iseq.c
      current_position -= 1 unless current_position == 0
      # find_line_no@iseq.c and get_line_info@iseq.c
      line_info_size = @gdb.cmd_get_value("p #{iseq}->line_info_size").to_i
      line_info_table = "#{iseq}->line_info_table"
      case line_info_size
      when 0
        return 0
      when 1
        return @gdb.cmd_get_value("p #{line_info_table}[0].line_no").to_i
      else
        (1...line_info_size).each do |i|
          position = @gdb.cmd_get_value("p #{line_info_table}[#{i}].position").to_i
          if position == current_position
            return @gdb.cmd_get_value("p #{line_info_table}[#{i}].line_no").to_i
          elsif position > current_position
            return @gdb.cmd_get_value("p #{line_info_table}[#{i - 1}].line_no").to_i
          end
        end
        return @gdb.cmd_get_value("p #{line_info_table}[#{line_info_size - 1}].line_no").to_i
      end
    end
    0
  end

  # NOTE: This logic is slow because many commands are sent to gdb.
  #       Fetch consts with 'ptype enum ruby_value_type' first and
  #       check types in Ruby.
  def rb_type(value)
    type_str = nil
    # IMMEDIATE_P
    if @gdb.cmd_get_value("p (int)(#{value}) & RUBY_IMMEDIATE_MASK") != '0'
      # FIXNUM_P
      if @gdb.cmd_get_value("p (int)(#{value}) & RUBY_FIXNUM_FLAG") != '0'
        type_str = 'RUBY_T_FIXNUM'
      # FLONUM_P
      elsif @gdb.cmd_get_value("p ((int)(#{value}) & RUBY_FLONUM_MASK) == RUBY_FLONUM_FLAG") != '0'
        type_str = 'RUBY_T_FLONUM'
      elsif @gdb.cmd_get_value("p (#{value}) == RUBY_Qtrue") != '0'
        type_str = 'RUBY_T_TRUE'
      # SYMBOL_P
      elsif @gdb.cmd_get_value("p (VALUE)(#{value}) & ~(~(VALUE)0 << RUBY_SPECIAL_SHIFT) == RUBY_SYMBOL_FLAG") != '0'
        type_str = 'RUBY_T_SYMBOL'
      elsif @gdb.cmd_get_value("p (#{value}) == RUBY_Qundef") != '0'
        type_str = 'RUBY_T_UNDEF'
      end
    elsif @gdb.cmd_get_value("p (int)(#{value}) & RUBY_FIXNUM_FLAG") != '0'
      # special consts
      const = @gdb.cmd_get_value("p (enum ruby_special_consts)(#{value})")
      # TODO: change to map
      case const
      when 'RUBY_Qnil'
        type_str = 'RUBY_T_NIL'
      when 'RUBY_Qfalse'
        type_str = 'RUBY_T_FALSE'
      end
    else
      # builtin type
      type_str = @gdb.cmd_get_value("p (enum ruby_value_type)(((struct RBasic*)(#{value}))->flags & RUBY_T_MASK)")
    end
  end

  def rstring_ptr(value_pointer)
    no_embed = @gdb.cmd_get_value("p ((struct RBasic *)(#{value_pointer}))->flags & #{RSTRING_NOEMBED}")
    if no_embed == '0'
      # embedded in struct
      @gdb.cmd_get_value("p (char *)((struct RString *)(#{value_pointer}))->as.ary")
    else
      # heap pointer
      @gdb.cmd_get_value("p (char *)((struct RString *)(#{value_pointer}))->as.heap.ptr")
    end
  end

  def rubyvm_cfunc_frame_p(cfp)
    @gdb.cmd_get_value("p (#{cfp}->flag & #{VM_FRAME_MAGIC_MASK}) == #{VM_FRAME_MAGIC_CFUNC}") != '0'
  end

  def do_hash(key, table)
    # NOTE: table->type->hash is always st_numhash
    key
  end

  def st_lookup(table, key)
    hash_val = do_hash(key, table)

    raise if @gdb.cmd_get_value("p (#{table})->entries_packed") != '0'
    raise if @gdb.cmd_get_value("p (#{table})->type->hash == st_numhash") == '0'
    raise if @gdb.cmd_get_value("p (#{table})->type->compare == st_numcmp") == '0'

    # TODO: check table->entries_packed
    bin_pos = @gdb.cmd_get_value("p (#{hash_val}) % (#{table})->num_bins")

    ptr = find_entry(table, key, hash_val, bin_pos)

    if ptr.hex == 0
      nil
    else
      value = @gdb.cmd_get_value("p ((struct st_table_entry *)(#{ptr}))->record")
      value
    end
  end

  def ptr_not_equal(table, ptr, hash_val, key)
    ptr =~ /(0x[0-9a-f]+)\z/
    ptr_num = $1.hex
    t_hash = @gdb.cmd_get_value("p (#{ptr})->hash")
    t_key = @gdb.cmd_get_value("p (#{ptr})->key")
    # NOTE: table->type->compare is always st_numcmp
    ptr_num != 0 and (t_hash != hash_val or t_key != key)
  end

  def find_entry(table, key, hash_val, bin_pos)
    ptr = @gdb.cmd_get_value("p (#{table})->as.big.bins[#{bin_pos}]")
    if ptr_not_equal(table, ptr, hash_val, key)
      next_ptr = @gdb.cmd_get_value("p (#{ptr})->next")
      while ptr_not_equal(table, next_ptr, hash_val, key)
        ptr = next_ptr
        next_ptr = @gdb.cmd_get_value("p (#{ptr})->next")
      end
      ptr = next_ptr
    end
    ptr =~ /(0x[0-9a-f]+)\z/
    $1
  end

  def rb_id2str(id)
    str_ptr = nil
    begin
      str_ptr = @gdb.cmd_get_pointer("p (struct RString *) rb_id2str(#{id})", 'struct RString')
    rescue
      str_ptr = st_lookup('global_symbols.id_str', id)
    end
    raise 'cannot get label from id' if str_ptr == nil
    rstring_ptr(str_ptr)
  end
end

class GDBRuby
  MAX_FRAMES = 30

  def initialize(config)
    @config = config
  end

  def trace
    @gdb = GDB.new(@config)
    @ri = RubyInternal.new(@gdb)
    puts "command:\n#{@gdb.exec_options.join(' ')}"
    puts ''
    @gdb.run do
      show_environ if @config['env', true]
      show_ruby_version
      show_backtrace
    end
  end

  def show_environ
    i = 0
    puts "environ:"
    @gdb.cmd_exec('info variables environ') # environ addr might be wrong. fix it.
    while true
      response = @gdb.cmd_get_value("p ((char **)environ)[#{i}]")
      break if response.empty? or response == '0x0'
      puts response
      i += 1
    end
    puts ''
  end

  def get_map_of_ruby_thread_pointer_to_gdb_thread_id
    # After 'set pagination off' is executed,
    # thread info is one line per thread.
    map = {}
    @gdb.cmd_exec('info threads').each_line do |line|
      if line =~ /\A[\s\*]+(\d+)/
        gdb_thread_id = $1
        @gdb.cmd_exec("thread #{gdb_thread_id}")
        @gdb.cmd_exec("backtrace").each_line do |bt_line|
          if bt_line =~ /\(th=(0x[0-9a-f]+)/
            ruby_thread_pointer = $1
            map[ruby_thread_pointer] = gdb_thread_id
            break
          end
        end
      end
    end
    map
  end

  def get_ruby_frame(frame_count, thread)
    # Accessor
    cfp = "(#{thread}->cfp + #{frame_count})"
    iseq = "#{cfp}->iseq"

    # Check iseq
    iseq_ptr = @gdb.cmd_get_pointer("p #{iseq}", 'rb_iseq_t')
    if iseq_ptr.hex != 0
      # TODO: check cfp->pc is null or not
      if @ruby_iseq_has_body
        iseq += '->body'
        iseq_body_ptr = @gdb.cmd_get_pointer("p #{iseq}", 'struct rb_iseq_constant_body')
        return if iseq_body_ptr == 0
      end

      iseq_type = @gdb.cmd_get_value("p #{iseq}->type").intern

      case iseq_type
      when :ISEQ_TYPE_TOP
        return
      end

      # Ruby function
      @prev_location = {
        :cfp => cfp,
        :iseq => iseq,
      }
      file_path = @ri.rstring_ptr(@gdb.cmd_get_value("p #{iseq}->location.absolute_path"))
      if file_path.empty?
        file_path = @ri.rstring_ptr(@gdb.cmd_get_value("p #{iseq}->location.path"))
      end
      label = @ri.rstring_ptr(@gdb.cmd_get_value("p #{iseq}->location.label"))
      base_label = @ri.rstring_ptr(@gdb.cmd_get_value("p #{iseq}->location.base_label"))
      line_no = @ri.rb_vm_get_sourceline(cfp, iseq)

      self_value = @gdb.cmd_get_value("p #{cfp}->self")
      self_type = @ri.rb_type(self_value)
      self_name = self_type == 'RUBY_T_CLASS' ? @gdb.cmd_get_value("p rb_class2name(#{cfp}->self)") : ''

      func_prefix = "#{self_name}#" unless self_name.empty?

      {
        :callee => label.empty? ? '(unknown)' : "#{func_prefix}#{label}",
        :args => '', # TODO: implement
        :source_path_line => "#{file_path}:#{line_no}",
      }
    elsif @ri.rubyvm_cfunc_frame_p(cfp)
      # C function

      me = nil
      %W(#{cfp}->me rb_vm_frame_method_entry(#{cfp})).each { |cmd|
        response = @gdb.cmd_exec("p #{cmd}")
        if response =~ /(\$\d+).*0x.*/
          me = $1
          break
        end
      }
      if me == nil
        raise "cannot get method entry from control frame"
      end

      mid = @gdb.cmd_get_value("p #{me}->def ? #{me}->def->original_id : #{me}->called_id")
      label = @ri.rb_id2str(mid)
      if @prev_location
        cfp = @prev_location[:cfp]
        iseq = @prev_location[:iseq]

        file_path = @ri.rstring_ptr(@gdb.cmd_get_value("p #{iseq}->location.absolute_path"))
        if file_path.empty?
          file_path = @ri.rstring_ptr(@gdb.cmd_get_value("p #{iseq}->location.path"))
        end
        line_no = @ri.rb_vm_get_sourceline(cfp, iseq)
      end

      {
        :callee => label,
        :args => '', # TODO: implement
        :source_path_line => "#{file_path}:#{line_no}",
      }
    end
  end

  def check_ruby_version
    @ruby_version = @gdb.cmd_get_value('p ruby_version')
    case @ruby_version.intern
    when :'2.0.0'
    end
    raise "unknown ruby version" unless @ruby_version
  end

  def show_ruby_version
    check_ruby_version
    puts 'ruby_version:'
    puts @ruby_version
    puts ''
  end

  def show_backtrace
    # TODO: List threads with ruby_current_vm->living_threads and dump all threads.
    #       Now, we dump only ruby_current_thread which is equivalent to ruby_current_vm->running_thread.

    thread_map = get_map_of_ruby_thread_pointer_to_gdb_thread_id

    dump_results = thread_map.map do |ruby_pointer, gdb_thread|
      output_lines = []

      ruby_thread = "((rb_thread_t *) #{ruby_pointer})"
      @gdb.cmd_exec("thread #{gdb_thread}")

      output_lines << "thread: #{gdb_thread}"
      output_lines << ''

      # Show C backtrace
      if @config['c_trace', true]
        c_bt = @gdb.cmd_exec('bt')
        output_lines << 'c_backtrace:'
        c_bt.each_line do |line|
          break if line == '(gdb) '
          output_lines << line
        end
        output_lines << ''
      end

      # Show Ruby backtrace
      output_lines << "ruby_backtrace:"
      cfp_count = @gdb.cmd_get_value("p (rb_control_frame_t *)(#{ruby_thread}->stack + #{ruby_thread}->stack_size) - #{ruby_thread}->cfp").to_i
      check_iseq_body = @gdb.cmd_exec("ptype struct rb_iseq_constant_body")
      @ruby_iseq_has_body = check_iseq_body =~ /type = struct rb_iseq_constant_body/

      frame_infos = []
      @prev_location = nil
      # NOTE: @prev_location may not be set properly when limited by MAX_FRAMES
      ([MAX_FRAMES, cfp_count].min - 1).downto(0).each do |count|
        frame_info = get_ruby_frame(count, ruby_thread)
        frame_infos << frame_info if frame_info
      end
      frame_infos.reverse.each_with_index do |fi, i|
        output_lines << "[#{frame_infos.length - i}] #{fi[:callee]}(#{fi[:args]}) <- #{fi[:source_path_line]}"
      end
      output_lines.join("\n")
    end

    puts dump_results.join("\n")
  end
end

def main
  config = GDBRubyConfig.new(ARGV)
  gdbruby = GDBRuby.new(config)
  gdbruby.trace
end

main

# vim: set expandtab ts=2 sw=2 nowrap ft=ruby ff=unix :
