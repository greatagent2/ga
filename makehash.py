#!/usr/bin/env python
# coding:utf-8
# makehash.py
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>


import sys
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))

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
from common import sysconfig as common
from common import FileUtil
from common import Config
from common import config
from common import __config__
from common import __sha1__
from common import __file__
from common import __version__

import os
import sys

import thread
import urllib2
import random

def makehash(dir,topdown=True):
	sha1 = Config(__sha1__)
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
	return sha1

FileUtil.if_has_file_remove(__sha1__)

def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	sys.stdout.write(common.info())
	makehash(dir)


if __name__ == '__main__':
	main()