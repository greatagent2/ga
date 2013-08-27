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
from common import __sign__
from common import __file__
from common import __version__

def sign(message):
	#message = base92.encode(message)
	privatefile = open('../greatagent.prikey')
	keydata = privatefile.read()
	prikey = rsa.PrivateKey.load_pkcs1(keydata)
	signature = rsa.sign(message, prikey, 'SHA-1')
	return base92.encode(signature)
def verify(message,signature):
	#message = base92.encode(message)
	signature = base92.decode(signature)
	publicfile = FileUtil.open('../greatagent.pubkey','r')
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
	
def do(message,filename):
	FileUtil.if_has_file_remove(filename)
	output = FileUtil.open(filename,"w")
	output.write(sign(message))
	output.close()
	input = FileUtil.open(filename,"r")
	ok = verify(message,input.read())
	input.close()
	return ok

def main():
	dir = FileUtil.cur_file_dir()
	print dir
	os.chdir(dir)
	input = open(__sha1__,"r")
	sha1 = input.read()
	input.close()
	print do(sha1,__sign__)



if __name__ == '__main__':
	main()