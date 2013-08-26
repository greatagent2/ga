#!/usr/bin/env python
# coding:utf-8
# autoupdate.py
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))

try:
	import gevent
	import gevent.socket
	import gevent.monkey
	gevent.monkey.patch_all()
except (ImportError, SystemError):
	gevent = None
try:
	import OpenSSL
except ImportError:
	OpenSSL = None

import re
import ConfigParser
import hashlib

class Config(object):

	def __init__(self,config):
		"""load config from proxy.ini"""
		ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
		self.FILENAME = config
		self.CONFIG = ConfigParser.ConfigParser()
		self.CONFIG.read(FileUtil.getfile(config))

	def writeconfig(self,section, option,str):
		if not self.CONFIG.has_section(section):
			self.CONFIG.add_section(section)
		self.CONFIG.set(section,option,str)
		f = open(FileUtil.getfile(self.FILENAME),'w') 
		self.CONFIG.write(f)
		f.close()
	
	def getconfig(self,section, option):
		return self.CONFIG.get(section, option)if self.CONFIG.has_option(section, option) else ''

	def getsection(self,section):
		return self.CONFIG.items(section) if self.CONFIG.has_section(section) else ''

class Common(object):
	"""Global Config Object"""

	def __init__(self):
		"""load config from ini"""
		self.CONFIG = config.CONFIG
		
		self.AUTOUPDATE_SERVER = self.CONFIG.get('autoupdate', self.CONFIG.get('autoupdate', 'server')).split('|')
		self.REGEX_PATH = tuple(x for x in self.CONFIG.get('regex', 'path').split('|') if x)
		
		random.shuffle(self.AUTOUPDATE_SERVER)

		
	def info(self):
		info = ''
		info += '------------------------------------------------------\n'
		info += 'GreatAgent Version	: %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
		info += 'Server          : %s\n' % '|'.join(self.AUTOUPDATE_SERVER)
		info += '------------------------------------------------------\n'
		return info


config = Common()