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

import errno
import time
import struct
import collections
import zlib
import functools
import re
import io
import fnmatch
import traceback
import random
import base64
import string
import hashlib
import threading
import thread
import socket
import ssl
import select
import Queue
import SocketServer
import ConfigParser
import BaseHTTPServer
import httplib
import urllib2
import urlparse
try:
	import OpenSSL
except ImportError:
	OpenSSL = None


import os
import sys
import re
import ConfigParser
import hashlib

__config__   = 'autoupdate.ini'
__sha1__   = 'sha1.ini'
__file__	 = 'autoupdate.py'

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
		self.CONFIG = config
		
		self.AUTOUPDATE_SERVER = tuple(x for x in self.CONFIG.get('autoupdate', self.CONFIG.get('autoupdate', 'server')).split('|') if x)
		self.REGEX_PATH = tuple(x for x in self.CONFIG.get('regex', 'path').split('|') if x)

		self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
		self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
		self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
		self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo') if self.CONFIG.has_option('listen', 'debuginfo') else 0

		self.GAE_PROFILE = self.CONFIG.get('google', 'profile')
		self.GAE_CRLF = self.CONFIG.getint('google', 'crlf')
		self.GAE_VALIDATE = self.CONFIG.getint('google', 'validate')
		self.GAE_OBFUSCATE = self.CONFIG.getint('google', 'obfuscate') if self.CONFIG.has_option('google', 'obfuscate') else 0
		self.GAE_USEFAKEHTTPS = self.CONFIG.getint('google', 'usefakehttps') if self.CONFIG.has_option('google', 'usefakehttps') else 0

		self.PROXY_ENABLE = self.CONFIG.getint('proxy', 'enable')
		self.PROXY_AUTODETECT = 0
		self.PROXY_HOST = self.CONFIG.get('proxy', 'host')
		self.PROXY_PORT = self.CONFIG.getint('proxy', 'port')
		self.PROXY_USERNAME = self.CONFIG.get('proxy', 'username')
		self.PROXY_PASSWROD = self.CONFIG.get('proxy', 'password')

		if not self.PROXY_ENABLE and self.PROXY_AUTODETECT:
			system_proxy = ProxyUtil.get_system_proxy()
			if system_proxy and self.LISTEN_IP not in system_proxy:
				_, username, password, address = ProxyUtil.parse_proxy(system_proxy)
				proxyhost, _, proxyport = address.rpartition(':')
				self.PROXY_ENABLE = 1
				self.PROXY_USERNAME = username
				self.PROXY_PASSWROD = password
				self.PROXY_HOST = proxyhost
				self.PROXY_PORT = int(proxyport)
		if self.PROXY_ENABLE:
			self.GOOGLE_MODE = 'https'
			self.proxy = 'https://%s:%s@%s:%d' % (self.PROXY_USERNAME or '', self.PROXY_PASSWROD or '', self.PROXY_HOST, self.PROXY_PORT)
		else:
			self.proxy = ''

		self.GOOGLE_MODE = self.CONFIG.get(self.GAE_PROFILE, 'mode')
		self.GOOGLE_WINDOW = self.CONFIG.getint(self.GAE_PROFILE, 'window') if self.CONFIG.has_option(self.GAE_PROFILE, 'window') else 4
		self.GOOGLE_HOSTS = [x for x in self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|') if x]
		self.GOOGLE_SITES = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|') if x)


		self.FETCHMAX_LOCAL = 3
		self.FETCHMAX_SERVER = ''

common = Common()


def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	print dir
	FileUtil.walk_dir(dir)
	for path, sha1v in sha1.getsection('FILE_SHA1'):
		newpath = path.replace('$path$',dir)
		print newpath + ' = ' + sha1v

if __name__ == '__main__':
	main()