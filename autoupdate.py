#!/usr/bin/env python2
#-*-encoding:utf-8-*-


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

from simpleproxy import LocalProxyServer
from simpleproxy import server
from simpleproxy import logging
from simpleproxy import common as proxyconfig

import os
import sys
import re
import ConfigParser
import hashlib
import thread
import urllib2
import random

__config__   = 'autoupdate.ini'
__sha1__   = 'sha1.ini'
__file__	 = 'autoupdate.py'
__version__ = '2.0.0'

class FileUtil(object):
	@staticmethod
	def walk_dir(dir,topdown=True):
		for root, dirs, files in os.walk(dir, topdown):
			for name in files:
				path = os.path.join(root,name)
				newpath = path.replace(dir,'$path$')
				regexpath = path.replace(dir,'.')
				if regexpath.startswith(common.REGEX_PATH):
					continue
				else:
					sha1v = FileUtil.sumfile(path)
					sha1.writeconfig('FILE_SHA1',newpath,sha1v)

	@staticmethod
	def getfile(filename):
		global __file__
		__file__ = os.path.abspath(__file__)
		if os.path.islink(__file__):
			__file__ = getattr(os, 'readlink', lambda x:x)(__file__)
		os.chdir(os.path.dirname(os.path.abspath(__file__)))
		return os.path.join(os.path.dirname(__file__), filename)

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
		m = hashlib.sha1()
		m.update(data)
		return m.hexdigest()

	@staticmethod
	def sumfile(fpath):
		input = open(fpath)
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


config = Config(__config__)
FileUtil.if_has_file_remove(__sha1__)
sha1 = Config(__sha1__)

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


common = Common()

class Updater(object):
	def __init__(self,serverurl,old_file_sha1_ini,dir):
		proxies = {'http':'%s:%s'%('127.0.0.1', proxyconfig.LISTEN_PORT),'https':'%s:%s'%('127.0.0.1', proxyconfig.LISTEN_PORT)}
		self.opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
		self.server = str(serverurl)
		self.old_file_sha1_ini = old_file_sha1_ini
		self.dir = dir
	def getfile(self,filename):
		while 1:
			try:
				response = self.opener.open(self.server+filename)
				file = response.read()
				return file
			except Exception as e:
				print e
				return
	def writefile(self,filename):
		file = self.getfile(filename)
		path = self.dir+filename
		old_file_sha1 = sha1.getconfig('FILE_SHA1','$path$'+filename)
		new_file_sha1 = FileUtil.get_file_sha1(file)
		if not old_file_sha1 == new_file_sha1:
			output = open(path,"w+b")
			output.write(file)
			print file.read()
			print 'Update	'+filename+'	OK!'
			output.close()
	def update(self):
		self.writefile('/hash.sha1')
		



def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	sys.stdout.write(common.info())
	sys.stdout.write(proxyconfig.info())
	thread.start_new_thread(server.serve_forever, tuple())
	FileUtil.walk_dir(dir)
	updater = Updater(common.AUTOUPDATE_SERVER[0],sha1,dir)
	updater.update()

	for path, sha1v in sha1.getsection('FILE_SHA1'):
		newpath = path.replace('$path$',dir)
		#print newpath + ' = ' + sha1v

if __name__ == '__main__':
	main()