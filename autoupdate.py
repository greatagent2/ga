#!/usr/bin/env python2
#-*-encoding:utf-8-*-

import os
import sys
import re
import ConfigParser
import hashlib

__config__   = 'proxy.ini'
__sha1__   = 'sha1.ini'
__file__     = 'autoupdate.py'

class FileUtil(object):
	@staticmethod
	def walk_dir(dir,fileinfo,topdown=True):
		for root, dirs, files in os.walk(dir, topdown):
			for name in files:
				path = os.path.join(root,name)
				sha1v = FileUtil.sumfile(path)
				newpath = path.replace(dir,'!DIR!')
				fileinfo.write(newpath + ':' + sha1v + '\n')
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
		self.CONFIG = ConfigParser.ConfigParser()
		self.CONFIG.read(FileUtil.getfile(config))

	def writeconfig(self,section, option,str):
		self.CONFIG.set(section,option,str)
		f = open(FileUtil.getfile(__config__),'w') 
		self.CONFIG.write(f)
		f.close()
	
	def getconfig(self,section, option):
		return self.CONFIG.get(section, option)if self.CONFIG.has_option(section, option) else ''
		
		
config = Config(__config__)
sha1 = Config(__sha1__)


def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	print dir
	fileinfo = open('list3.txt','w')
	FileUtil.if_has_file_remove(__sha1__)
	FileUtil.walk_dir(dir,fileinfo)

if __name__ == '__main__':
	main()