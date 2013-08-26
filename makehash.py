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

from simpleproxy import LocalProxyServer
from simpleproxy import server
from simpleproxy import logging
from simpleproxy import common as proxyconfig
from common import sysconfig as common
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





FileUtil.if_has_file_remove(__sha1__)
sha1 = Config(__sha1__)


def main():
	dir = FileUtil.cur_file_dir()
	os.chdir(dir)
	sys.stdout.write(common.info())
	sys.stdout.write(proxyconfig.info())
	thread.start_new_thread(server.serve_forever, tuple())
	FileUtil.walk_dir(dir)
	updater = Updater(common.AUTOUPDATE_SERVER[0],sha1,dir)
	#updater.update()

	#for path, sha1v in sha1.getsection('FILE_SHA1'):
		#newpath = path.replace('$path$',dir)
		#print newpath + ' = ' + sha1v

if __name__ == '__main__':
	main()