#!/usr/bin/env python
# coding:utf-8
# by:wwqgtxx,phus



import sys
sys.version_info[0] == 2 and reload(sys).setdefaultencoding('utf-8')
import os
import re


try:
	import ctypes
except ImportError:
	ctypes = None

try:
	import gevent
	import gevent.monkey
	import gevent.timeout
	gevent.monkey.patch_all()
except ImportError:
	if os.name == 'nt':
		sys.stderr.write('WARNING: python-gevent not installed. `https://github.com/SiteSupport/gevent/downloads`\n')
	else:
		sys.stderr.write('WARNING: python-gevent not installed. `curl -k -L http://git.io/I9B7RQ|sh`\n')
	sys.exit(-1)

import ssl
import socket
import ConfigParser
import update

def main():
	sock = socket.create_connection(('173.194.78.125', 443))
	ssl_sock = ssl.wrap_socket(sock)
	peer_cert = ssl_sock.getpeercert(True)
	print peer_cert

if __name__ == '__main__':
	main()