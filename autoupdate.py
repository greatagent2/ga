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
from simpleproxy import common as proxyconfig

import os
import sys
import re
import ConfigParser
import hashlib
import thread
import urllib2

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
	def sumfile(fpath):
		return FileUtil.get_file_sha1(open(fpath))

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
		
		self.AUTOUPDATE_SERVER = tuple(x for x in self.CONFIG.get('autoupdate', self.CONFIG.get('autoupdate', 'server')).split('|') if x)
		self.REGEX_PATH = tuple(x for x in self.CONFIG.get('regex', 'path').split('|') if x)

		
	def info(self):
		info = ''
		info += '------------------------------------------------------\n'
		info += 'GreatAgent Version	: %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
		info += '------------------------------------------------------\n'
		return info


common = Common()

class Updater(object):
	def __init__(self):
		return
	def update(self):
		proxies = {'http':'%s:%s'%('127.0.0.1', proxyconfig.LISTEN_PORT),'https':'%s:%s'%('127.0.0.1', proxyconfig.LISTEN_PORT)}
		opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
		response = opener.open('https://gfangqiang.googlecode.com/svn/bootstrap.txt')
		open("bootstrap.txt","w+b").write(response.read())
		
updater = Updater()


def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	print dir
	sys.stdout.write(common.info())
	sys.stdout.write(proxyconfig.info())
	thread.start_new_thread(server.serve_forever, tuple())
	updater.update()
	FileUtil.walk_dir(dir)
	for path, sha1v in sha1.getsection('FILE_SHA1'):
		newpath = path.replace('$path$',dir)
		print newpath + ' = ' + sha1v

if __name__ == '__main__':
	main()