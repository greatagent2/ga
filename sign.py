#!/usr/bin/env python
# coding:utf-8
# sign.py
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

import sys
import os
import os
import glob

sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.*' % os.path.dirname(os.path.abspath(__file__)))
import rsa
import base92

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

from common import sysconfig as common
from common import FileUtil
from common import Config
from common import config
from common import __config__
from common import __sha1__
from common import __file__
from common import __version__

def sign(message):
	privatefile = open('../greatagent.prikey')
	keydata = privatefile.read()
	prikey = rsa.PrivateKey.load_pkcs1(keydata)
	signature = rsa.sign(message, prikey, 'SHA-1')
	return base92.encode(signature)
def verify(message,signature):
	signature = base92.decode(signature)
	publicfile = open('../greatagent.pubkey')
	keydata = publicfile.read()
	pubkey = rsa.PublicKey.load_pkcs1(keydata)
	try:
		rsa.verify(message,signature, pubkey)
		return True
	except rsa.pkcs1.VerificationError:
		return False
def make():
	(pubkey, privkey) = rsa.newkeys(2048)
	print pubkey.save_pkcs1()
	print '----------------------------------'
	print privkey.save_pkcs1()

def main():
	dir = FileUtil.cur_file_dir()
	print dir
	os.chdir(dir)
	#sys.stdout.write(common.info())
	print verify("wwqgtxx",sign("wwqgtxx"))



if __name__ == '__main__':
	main()