#!/usr/bin/env python
# coding:utf-8
# common.py
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

__config__   = 'autoupdate.ini'
__sha1__   = 'sha1.ini'
__sign__   = 'sha1.sign'
__git__   = 'git.txt'
__versionfile__ = 'version'
__pubkey__   = './greatagent2.pubkey'
__prikey__   = '../greatagent2.prikey'
__author__   = 'Wang Wei Qiang <wwqgtxx@gmail.com>'
__names__   = 'GreatAgent2-GA'
__version__ = '2.0.0'
__file__	 = 'autoupdate.py'

import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))

try:
	if 'threading' in sys.modules:
		del sys.modules['threading']
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
import random
import shutil

import rsa,base92,pyasn1

class FileUtil(object):
	@staticmethod
	def getfile(filename):
		global __file__
		__file__ = os.path.abspath(__file__)
		if os.path.islink(__file__):
			__file__ = getattr(os, 'readlink', lambda x:x)(__file__)
		os.chdir(os.path.dirname(os.path.abspath(__file__)))
		return os.path.join(os.path.dirname(__file__), filename)

	@staticmethod
	def has_file(filename):
		return os.path.isfile(FileUtil.getfile(filename))

	@staticmethod
	def delete_dir(dir):
		shutil.rmtree(dir)

	@staticmethod
	def if_has_file_remove(filename):
		if os.path.isfile(FileUtil.getfile(filename)):
			os.remove(FileUtil.getfile(filename)) 

	@staticmethod
	def get_file_sha1(f):
		m = hashlib.sha1()
		while True:
			data = f.read(10240)
			if not data:
				break
			m.update(data)
		return m.hexdigest()
		
	@staticmethod
	def get_data_sha1(data):
		m = hashlib.sha1(data)
		return m.hexdigest()

	@staticmethod
	def sumfile(fpath):
		input = FileUtil.open(fpath,'rb')
		sum = FileUtil.get_file_sha1(input)
		input.close()
		return sum

	@staticmethod
	def cur_file_dir():
		path = sys.path[0]
		if os.path.isdir(path):
			return path
		elif os.path.isfile(path):
			return os.path.dirname(path)

	@staticmethod
	def open(path,type):
		path = path.replace('\\','/')
		if type.endswith('w') or type.startswith('w'):
			pathdir = ''
			paths = path.split('/')
			i = 1
			for str in paths:
				if i == len(paths):
					break
				if not str == '':
					pathdir += '/'+str
				i = i+1
			str = ''
			pathdir = pathdir[1:]
			if not os.path.isdir(pathdir) and not pathdir == '':
				pathdir = pathdir.replace((FileUtil.cur_file_dir()).replace('\\','/')+'/','')
				dir = ''
				for str in pathdir.split('/'):
					if not str == '':
						dir = dir+'/'+str
						os.mkdir(dir)
						print 'MakeDir	'+dir+'				OK!'
			if path.endswith(sysconfig.REGEX_ONLYW)or type.endswith('b'):
				return open(path,type)
			else:
				return open(path,type+"b")
		elif type.endswith('r') or type.startswith('r'):
			if path.endswith(sysconfig.REGEX_ONLYR)or type.endswith('b'):
				return open(path,type)
			else:
				return open(path,type+"b")
		else:
			return
			
class MyConfigParser(ConfigParser.ConfigParser):
	def optionxform(self, optionstr): 
		return optionstr



class Config(object):

	def __init__(self,config):
		"""load config from proxy.ini"""
		ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
		self.FILENAME = config
		self.CONFIG = MyConfigParser()
		self.CONFIG.read(FileUtil.getfile(config))

	def writeconfig(self,section, option,str):
		if not self.CONFIG.has_section(section):
			self.CONFIG.add_section(section)
		self.CONFIG.set(section,option,str)
		f = FileUtil.open(FileUtil.getfile(self.FILENAME),'w') 
		self.CONFIG.write(f)
		f.close()
	
	def getconfig(self,section, option):
		return self.CONFIG.get(section, option)if self.CONFIG.has_option(section, option) else ''

	def getsection(self,section):
		return self.CONFIG.items(section) if self.CONFIG.has_section(section) else ''

config = Config(__config__)

class Common(object):
	"""Global Config Object"""

	def __init__(self):
		"""load config from ini"""
		self.CONFIG = config.CONFIG
		
		self.AUTOUPDATE_SERVER_STR = self.CONFIG.get('autoupdate', 'server')
		self.AUTOUPDATE_SERVER = self.CONFIG.get('autoupdate',self.AUTOUPDATE_SERVER_STR ).split('|')
		self.REGEX_START = tuple(x for x in self.CONFIG.get('regex', 'start').split('|') if x)
		self.REGEX_END = tuple(x for x in self.CONFIG.get('regex', 'end').split('|') if x)
		self.REGEX_ONLYW = tuple(x for x in self.CONFIG.get('regex', 'onlyw').split('|') if x)
		self.REGEX_ONLYR = tuple(x for x in self.CONFIG.get('regex', 'onlyr').split('|') if x)
		
		random.shuffle(self.AUTOUPDATE_SERVER)

		
	def info(self):
		info = ''
		info += '------------------------------------------------------\n'
		info += 'GreatAgent Version	: %s \n'% (__version__)
		info += 'RunTime            :python/%s %spyopenssl/%s rsa/%s PyASN1/%s base92/%s\n' % (sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'),rsa.__version__,pyasn1.__version__,base92.__version__)
		info += 'Update Server      : %s\n' % '|'.join(self.AUTOUPDATE_SERVER)
		info += '------------------------------------------------------\n'
		return info


sysconfig = Common()