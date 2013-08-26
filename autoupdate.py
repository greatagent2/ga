#!/usr/bin/env python2
#-*-encoding:utf-8-*-

import os
import sys
import re
import ConfigParser
import hashlib

__config__   = 'proxy.ini'
__file__     = 'autoupdate.py'

class Common(object):

	def __init__(self,config):
		"""load config from proxy.ini"""
		ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
		self.CONFIG = ConfigParser.ConfigParser()
		self.CONFIG.read(os.path.join(os.path.dirname(__file__), config))
		self.IPS = []


	def getfile(self,filename):
		global __file__
		__file__ = os.path.abspath(__file__)
		if os.path.islink(__file__):
			__file__ = getattr(os, 'readlink', lambda x:x)(__file__)
		os.chdir(os.path.dirname(os.path.abspath(__file__)))
		return os.path.join(os.path.dirname(__file__), filename)

	def ifhasfile(self):
		if os.path.isfile(self.getfile(__filename__)):
			os.remove(self.getfile(__filename__)) 
		
	def write(self,str_ips):
		f = open(self.getfile(__filename__),'a+') 
		print str_ips
		f.write(str_ips)
		f.close()

	def getln(self):
		if os.name == 'nt':
			return '\r\n'
		else:
			return '\n'

	def writeln(self):
		self.write(self.getln())
	
	def writeline(self):
		self.writeln()
		self.write('-'*60)
		self.writeln()
	
	def writeip(self,ip):
		self.write(ip)
		common.IPS.append(ip)

	def writeips(self,section, option):
		str_ips = ''
		if self.IPS!=[]:
			for item in self.IPS:
				str_ips = str_ips+item
			print str_ips
			self.writeconfig(section, option,str_ips)
			self.IPS = []

	def writeconfig(self,section, option,str):
		self.CONFIG.set(section,option,str)
		f = open(self.getfile(__config__),'w') 
		self.CONFIG.write(f)
		f.close()
	
	def getconfig(self,section, option):
		return self.CONFIG.get(section, option)if self.CONFIG.has_option(section, option) else ''
		
		
common = Common(__config__)

class FileUtil(object):
	@staticmethod
	def walk_dir(dir,fileinfo,topdown=True):
		for root, dirs, files in os.walk(dir, topdown):
			for name in files:
				path = os.path.join(root,name)
				md5v = sumfile(path)
				newpath = path.replace(dir,'')
				fileinfo.write(newpath + ':' + md5v + '\n')

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

def main():
	dir = FileUtil.cur_file_dir()
	print FileUtil.cur_file_dir()
	fileinfo = open('list3.txt','w')
	FileUtil.walk_dir(dir,fileinfo)

if __name__ == '__main__':
	main()