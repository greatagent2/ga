#!/usr/bin/env python
# coding:utf-8
# Based on GoAgent 3.1.16 by Phus Lu <phus.lu@gmail.com>
# Author: Wang Wei Qiang <wwqgtxx@gmail.com>

__version__ = '3.0.0'

import sys
import os
import glob

reload(sys).setdefaultencoding('UTF-8')
sys.dont_write_bytecode = True
sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
sys.path += glob.glob('%s/lib/*.egg' % os.path.dirname(os.path.abspath(__file__)))


try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
    sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')

import errno
import time
import struct
import collections
import binascii
import zlib
import itertools
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
import urllib
import urllib2
import urlparse
try:
    import dnslib
except ImportError:
    dnslib = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import pygeoip
except ImportError:
    pygeoip = None


HAS_PYPY = hasattr(sys, 'pypy_version_info')
NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


class Logging(type(sys)):
    CRITICAL = 50
    FATAL = CRITICAL
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0

    def __init__(self, *args, **kwargs):
        self.level = self.__class__.INFO
        self.__set_error_color = lambda: None
        self.__set_warning_color = lambda: None
        self.__set_debug_color = lambda: None
        self.__reset_color = lambda: None
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            if os.name == 'nt':
                import ctypes
                SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
                GetStdHandle = ctypes.windll.kernel32.GetStdHandle
                self.__set_error_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
                self.__set_warning_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x06)
                self.__set_debug_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x002)
                self.__reset_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
            elif os.name == 'posix':
                self.__set_error_color = lambda: sys.stderr.write('\033[31m')
                self.__set_warning_color = lambda: sys.stderr.write('\033[33m')
                self.__set_debug_color = lambda: sys.stderr.write('\033[32m')
                self.__reset_color = lambda: sys.stderr.write('\033[0m')

    @classmethod
    def getLogger(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def basicConfig(self, *args, **kwargs):
        self.level = int(kwargs.get('level', self.__class__.INFO))
        if self.level > self.__class__.DEBUG:
            self.debug = self.dummy

    def log(self, level, fmt, *args, **kwargs):
        sys.stderr.write('%s - [%s] %s\n' % (level, time.ctime()[4:-5], fmt % args))

    def dummy(self, *args, **kwargs):
        pass

    def debug(self, fmt, *args, **kwargs):
        pass

    def info(self, fmt, *args, **kwargs):
        pass

    def warning(self, fmt, *args, **kwargs):
        self.__set_warning_color()
        self.log('WARNING', fmt, *args, **kwargs)
        self.__reset_color()

    def warn(self, fmt, *args, **kwargs):
        self.warning(fmt, *args, **kwargs)

    def error(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('ERROR', fmt, *args, **kwargs)
        self.__reset_color()

    def exception(self, fmt, *args, **kwargs):
        self.error(fmt, *args, **kwargs)
        sys.stderr.write(traceback.format_exc() + '\n')

    def critical(self, fmt, *args, **kwargs):
        self.__set_error_color()
        self.log('CRITICAL', fmt, *args, **kwargs)
        self.__reset_color()
logging = sys.modules['logging'] = Logging('logging')


class LRUCache(object):
    """http://pypi.python.org/pypi/lru/"""

    def __init__(self, max_items=100):
        self.cache = {}
        self.key_order = []
        self.max_items = max_items

    def __setitem__(self, key, value):
        self.cache[key] = value
        self._mark(key)

    def __getitem__(self, key):
        value = self.cache[key]
        self._mark(key)
        return value

    def __contains__(self, key):
        return key in self.cache

    def _mark(self, key):
        if key in self.key_order:
            self.key_order.remove(key)
        self.key_order.insert(0, key)
        if len(self.key_order) > self.max_items:
            index = self.max_items // 2
            delitem = self.cache.__delitem__
            key_order = self.key_order
            any(delitem(key_order[x]) for x in xrange(index, len(key_order)))
            self.key_order = self.key_order[:index]

    def clear(self):
        self.cache = {}
        self.key_order = []

class CertUtil(object):
    """CertUtil module, based on mitmproxy"""

    ca_vendor = 'GoAgent'
    ca_certdir = 'certs'
    ca_lock = threading.Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationName = CertUtil.ca_vendor
        subj.organizationalUnitName = '%s Root' % CertUtil.ca_vendor
        subj.commonName = '%s CA' % CertUtil.ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
            OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
            OpenSSL.crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'),
            OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
            OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca():
        key, ca = CertUtil.create_ca()
        with open(CertUtil.ca_keyfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

    @staticmethod
    def _get_cert(commonname, sans=()):
        content = """
-----BEGIN CERTIFICATE-----
MIIDUjCCAjoCAQAwDQYJKoZIhvcNAQEFBQAwbzEVMBMGA1UECxMMR29BZ2VudCBS
b290MRAwDgYDVQQKEwdHb0FnZW50MRMwEQYDVQQDEwpHb0FnZW50IENBMREwDwYD
VQQIEwhJbnRlcm5ldDELMAkGA1UEBhMCQ04xDzANBgNVBAcTBkNlcm5ldDAeFw0x
MTA0MjAxNzM3MzVaFw0zMTA0MjAxNzM3MzVaMG8xFTATBgNVBAsTDEdvQWdlbnQg
Um9vdDEQMA4GA1UEChMHR29BZ2VudDETMBEGA1UEAxMKR29BZ2VudCBDQTERMA8G
A1UECBMISW50ZXJuZXQxCzAJBgNVBAYTAkNOMQ8wDQYDVQQHEwZDZXJuZXQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0jV3yx3yGAHlQqzm4fbVascvT
nyCdtParWBnQn5A3U9pJjI47SCo8j7FfeoYSL0mHbJ0mjafTnw+/ewb09AQIkdEl
n6smojl7NOKs1Yhh0yldB6kQWiBPr/XKMBskmvcyjJEqkU6hwtibASaAZt+q5clT
BJ2XRaeAaMDeDbYDchFa7MTNhoQMdQFu1UhqkJxtuVMBEs1/qPbx5O9pqy1RgAeK
WvxyCzVRi2hHaTns+weZBJ6N71afyvr1etGqqtWVpjpobk1ZFBYk4xpznCbm4iqP
Ar9nqdGDw1IJIdX0DyMJIJrpwOf94pAK9v6zG0jnsbMqromL18kEMXZgYSMlAgMB
AAEwDQYJKoZIhvcNAQEFBQADggEBAASiRZFCcgQ8VsncB8wKG+bmN9UZhXLJYRGp
m3KIUy/zG6mMWG/3TgkPn8ivNAkrk+1ul5SrRvot/Q7XWpb0/yKX0faX/512JF2G
220gopqo4amj+g7SBKxzW8VhLQF6dm99eUd27JbAzi5VKXR0dMFECk2rFlA5gAR5
zzFijaXHuObMtd2S292wji79JWocA0z6WVM5Qokw4hRTsXWfXL0BJTL3i/xRrEzW
sdecYFpNhaEKldjegazoqAqiAMJj7PDU1AqdprNsq+3/tAmCvn0URkas4QhkvtqS
FO6OGm/PZe5GbkBpAKdfLYFfEMO17SAGHHqAsIKAFfuHYONRGSM=
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtI1d8sd8hgB5UKs5uH21WrHL058gnbT2q1gZ0J+QN1PaSYyO
O0gqPI+xX3qGEi9Jh2ydJo2n058Pv3sG9PQECJHRJZ+rJqI5ezTirNWIYdMpXQep
EFogT6/1yjAbJJr3MoyRKpFOocLYmwEmgGbfquXJUwSdl0WngGjA3g22A3IRWuzE
zYaEDHUBbtVIapCcbblTARLNf6j28eTvaastUYAHilr8cgs1UYtoR2k57PsHmQSe
je9Wn8r69XrRqqrVlaY6aG5NWRQWJOMac5wm5uIqjwK/Z6nRg8NSCSHV9A8jCSCa
6cDn/eKQCvb+sxtI57GzKq6Ji9fJBDF2YGEjJQIDAQABAoIBACB3n2JN/xV1tlsM
P1fuuxLxD+8hGVNivEy5jgLW/q8EVCePr+/3HSlAyauas8tHV5iTrnrFVF2Yp9NO
A0U/MA5+cjaqzLMozt9Z9j0QNPMqbrC89Ojs3AyYXsGZ/veJKlSbtGsMMDCkgiD1
hv/l/+iSY66bEN+n9eQAclY77vQVXLSoCMReVfbdUxU9Q1MywODGf5Kng84gTyT/
zd+xEfFHz8zbCDyw3Hd3hGJ2FxN+yFz1uI29ORb3/R7N9dZgsWf2fsfiRVPGuhAH
RNlDockImB+BKeidx14sMim5p7s8heVYkBVW3SIOEReqz59b8x4QVhhZrzYWSHNq
Gi0pLiECgYEA26v6b+rsxT//PznJSEhLyrg1Jo6XeWmFlwZY0KoipH6sxX/YPrDZ
bOPN8KvAHtRltRLFs3L2iRaO2jltjxHGVF4FSYrf5KSExuj6/ABHxWM0YtezfDwR
hU1ORg5QwVegMoOgsphS8ts2xn6T6wIwpBgtFPY84A52IBVn5CHuQtkCgYEA0mk5
EpnZfmMT5ldcZ7JlZrxfWKvDHIcuA0neIBsd4oIcEfRhDC3TolH6pB4z4SCqyYw3
t5HMiTx8yz074mycTcOcXO1Cs49kMZwbzKziRXpUdCW4EIo0DG+6LqwetPgYzozg
FeTiGQBHqjrzjBLZ3RfozICbo7dvYHkVLK92my0CgYBWNBjlDnW3ujN6Jj0cxnIn
rT3+UXqTxJsN9wmnaPyLPMKkBlVf1JqeJo9MYLnV31fCRQmcMAMbLOUGMf8SY9FG
jlbY00ylNwJ75DWJ6ro/dXy7RRZELHZbr0iGKVv7Y12UNR88tpXmg6vtHQMC+CsK
Wgpm7XJaIpKsaHoKhl4vkQKBgBBBTsZwGkxYTSZDY4EjWBAax2brRhSDIPviDgX+
8k0YbiC493Jga/QjTzC0oJ9ozajqazeETP/hK2bsIR858s1TKlZHghqrHjty6vbh
+E0TyUh7zX+BncnEK+cFJw4mCIyUd49ZcloqGl89VKlin3AkM7jwypVYS4Nxd0BP
geM1AoGBALOWNmYm9d4gRhUv14oJRiA+e+4evswiWvVdnS6UJ4tst0NlEKWahtpR
kdAjav8WV1n6IbkJC2L743Ozjb63z5w6p5O7OtTyYUWbLt1hvNkHlkNP8AjRQP8E
+N2jjrMAdbEwahPNAX9QlzHpF62AfEGQ3oODUm06TGTq+yAPSyYm
-----END RSA PRIVATE KEY-----

"""
        key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
        ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.countryName = 'CN'
        subj.stateOrProvinceName = 'Internet'
        subj.localityName = 'Cernet'
        subj.organizationalUnitName = '%s Branch' % CertUtil.ca_vendor
        if commonname[0] == '.':
            subj.commonName = '*' + commonname
            subj.organizationName = '*' + commonname
            sans = ['*'+commonname] + [x for x in sans if x != '*'+commonname]
        else:
            subj.commonName = commonname
            subj.organizationName = commonname
            sans = [commonname] + [x for x in sans if x != commonname]
        #req.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans)).encode()])
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        try:
            cert.set_serial_number(int(hashlib.md5(commonname.encode('utf-8')).hexdigest(), 16))
        except OpenSSL.SSL.Error:
            cert.set_serial_number(int(time.time()*1000))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        if commonname[0] == '.':
            sans = ['*'+commonname] + [s for s in sans if s != '*'+commonname]
        else:
            sans = [commonname] + [s for s in sans if s != commonname]
        #cert.add_extensions([OpenSSL.crypto.X509Extension(b'subjectAltName', True, ', '.join('DNS: %s' % x for x in sans))])
        cert.sign(key, 'sha1')

        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        return certfile

    @staticmethod
    def get_cert(commonname, sans=()):
        if commonname.count('.') >= 2 and len(commonname.split('.')[-2]) > 4:
            commonname = '.'+commonname.partition('.')[-1]
        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        elif OpenSSL is None:
            return CertUtil.ca_keyfile
        else:
            with CertUtil.ca_lock:
                if os.path.exists(certfile):
                    return certfile
                return CertUtil._get_cert(commonname, sans)

    @staticmethod
    def import_ca(certfile):
        commonname = os.path.splitext(os.path.basename(certfile))[0]
        if OpenSSL:
            try:
                with open(certfile, 'rb') as fp:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, fp.read())
                    commonname = next(v.decode() for k, v in x509.get_subject().get_components() if k == b'O')
            except Exception as e:
                logging.error('load_certificate(certfile=%r) failed:%s', certfile, e)
        if sys.platform.startswith('win'):
            import ctypes
            with open(certfile, 'rb') as fp:
                certdata = fp.read()
                if certdata.startswith(b'-----'):
                    begin = b'-----BEGIN CERTIFICATE-----'
                    end = b'-----END CERTIFICATE-----'
                    certdata = base64.b64decode(b''.join(certdata[certdata.find(begin)+len(begin):certdata.find(end)].strip().splitlines()))
                crypt32 = ctypes.WinDLL(b'crypt32.dll'.decode())
                store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x20000, b'ROOT'.decode())
                if not store_handle:
                    return -1
                if crypt32.CertFindCertificateInStore(store_handle, 0x1, 0, 0x80007, CertUtil.ca_vendor.decode(), None):
                    return 0
                ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
                crypt32.CertCloseStore(store_handle, 0)
                del crypt32
                return 0 if ret else -1
        elif sys.platform == 'darwin':
            return os.system(('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile.decode('utf-8'))).encode('utf-8'))
        elif sys.platform.startswith('linux'):
            import platform
            platform_distname = platform.dist()[0]
            if platform_distname == 'Ubuntu':
                pemfile = "/etc/ssl/certs/%s.pem" % commonname
                new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
                if not os.path.exists(pemfile):
                    return os.system('cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile))
            elif any(os.path.isfile('%s/certutil' % x) for x in os.environ['PATH'].split(os.pathsep)):
                return os.system('certutil -L -d sql:$HOME/.pki/nssdb | grep "%s" || certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "%s" -i "%s"' % (commonname, commonname, certfile))
            else:
                logging.warning('please install *libnss3-tools* package to import GoAgent root ca')
        return 0

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_keyfile)
        certdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_certdir)
        if not os.path.exists(capath):
            if not OpenSSL:
                logging.critical('CA.key is not exist and OpenSSL is disabled, ABORT!')
                sys.exit(-1)
            if os.path.exists(certdir):
                if os.path.isdir(certdir):
                    any(os.remove(x) for x in glob.glob(certdir+'/*.crt')+glob.glob(certdir+'/.*.crt'))
                else:
                    os.remove(certdir)
                    os.mkdir(certdir)
            CertUtil.dump_ca()
        if glob.glob('%s/*.key' % CertUtil.ca_certdir):
            for filename in glob.glob('%s/*.key' % CertUtil.ca_certdir):
                try:
                    os.remove(filename)
                    os.remove(os.path.splitext(filename)[0]+'.crt')
                except EnvironmentError:
                    pass
        #Check CA imported
        if CertUtil.import_ca(capath) != 0:
            logging.warning('install root certificate failed, Please run as administrator/root/sudo')
        #Check Certs Dir
        if not os.path.exists(certdir):
            os.makedirs(certdir)


class SSLConnection(object):
    """OpenSSL Connection Wapper"""

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._connection = OpenSSL.SSL.Connection(context, sock)
        self._makefile_refs = 0

    def __getattr__(self, attr):
        if attr not in ('_context', '_sock', '_connection', '_makefile_refs'):
            return getattr(self._connection, attr)

    def __wait_sock_io(self, sock, io_func, *args, **kwargs):
        timeout = self._sock.gettimeout() or 0.1
        fd = self._sock.fileno()
        while True:
            try:
                return io_func(*args, **kwargs)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                _, _, errors = select.select([fd], [], [fd], timeout)
                if errors:
                    break
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                _, _, errors = select.select([], [fd], [fd], timeout)
                if errors:
                    break

    def accept(self):
        sock, addr = self._sock.accept()
        client = OpenSSL.SSL.Connection(sock._context, sock)
        return client, addr

    def do_handshake(self):
        return self.__wait_sock_io(self._sock, self._connection.do_handshake)

    def connect(self, *args, **kwargs):
        return self.__wait_sock_io(self._sock, self._connection.connect, *args, **kwargs)

    def send(self, data, flags=0):
        try:
            return self.__wait_sock_io(self._sock, self._connection.send, data, flags)
        except OpenSSL.SSL.SysCallError as e:
            if e[0] == -1 and not data:
                # errors when writing empty strings are expected and can be ignored
                return 0
            raise

    def recv(self, bufsiz, flags=0):
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        try:
            return self.__wait_sock_io(self._sock, self._connection.recv, bufsiz, flags)
        except OpenSSL.SSL.ZeroReturnError:
            return ''

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.sendall(buf, flags)

    def close(self):
        if self._makefile_refs < 1:
            self._connection = None
            if self._sock:
                socket.socket.close(self._sock)
        else:
            self._makefile_refs -= 1

    def makefile(self, mode='r', bufsize=-1):
        self._makefile_refs += 1
        return socket._fileobject(self, mode, bufsize, close=True)


def parse_hostport(host, default_port=80):
    m = re.match(r'(.+)[#](\d+)$', host)
    if m:
        return m.group(1).strip('[]'), int(m.group(2))
    else:
        return host.strip('[]'), default_port


def dnslib_resolve_over_udp(query, dnsservers, timeout, **kwargs):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93
    http://support.microsoft.com/kb/241352
    """
    if not isinstance(query, (basestring, dnslib.DNSRecord)):
        raise TypeError('query argument requires string/DNSRecord')
    blacklist = kwargs.get('blacklist', ())
    turstservers = kwargs.get('turstservers', ())
    dns_v4_servers = [x for x in dnsservers if ':' not in x]
    dns_v6_servers = [x for x in dnsservers if ':' in x]
    sock_v4 = sock_v6 = None
    socks = []
    if dns_v4_servers:
        sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socks.append(sock_v4)
    if dns_v6_servers:
        sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        socks.append(sock_v6)
    timeout_at = time.time() + timeout
    try:
        for _ in xrange(4):
            try:
                for dnsserver in dns_v4_servers:
                    if isinstance(query, basestring):
                        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(query))
                    query_data = query.pack()
                    sock_v4.sendto(query_data, parse_hostport(dnsserver, 53))
                for dnsserver in dns_v6_servers:
                    if isinstance(query, basestring):
                        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(query, qtype=dnslib.QTYPE.AAAA))
                    query_data = query.pack()
                    sock_v6.sendto(query_data, parse_hostport(dnsserver, 53))
                while time.time() < timeout_at:
                    ins, _, _ = select.select(socks, [], [], 0.1)
                    for sock in ins:
                        reply_data, reply_address = sock.recvfrom(512)
                        reply_server = reply_address[0]
                        record = dnslib.DNSRecord.parse(reply_data)
                        iplist = [str(x.rdata) for x in record.rr if x.rtype in (1, 28, 255)]
                        if any(x in blacklist for x in iplist):
                            logging.debug('query=%r dnsservers=%r record bad iplist=%r', query, dnsservers, iplist)
                        elif record.header.rcode and not iplist and reply_server in turstservers:
                            logging.info('query=%r trust reply_server=%r record rcode=%s', query, reply_server, record.header.rcode)
                            return record
                        elif iplist:
                            logging.debug('query=%r reply_server=%r record iplist=%s', query, reply_server, iplist)
                            return record
                        else:
                            logging.debug('query=%r reply_server=%r record null iplist=%s', query, reply_server, iplist)
                            continue
            except socket.error as e:
                logging.warning('handle dns query=%s socket: %r', query, e)
        raise socket.gaierror(11004, 'getaddrinfo %r from %r failed' % (query, dnsservers))
    finally:
        for sock in socks:
            sock.close()


def dnslib_resolve_over_tcp(query, dnsservers, timeout, **kwargs):
    """dns query over tcp"""
    if not isinstance(query, (basestring, dnslib.DNSRecord)):
        raise TypeError('query argument requires string/DNSRecord')
    blacklist = kwargs.get('blacklist', ())
    def do_resolve(query, dnsserver, timeout, queobj):
        if isinstance(query, basestring):
            qtype = dnslib.QTYPE.AAAA if ':' in dnsserver else dnslib.QTYPE.A
            query = dnslib.DNSRecord(q=dnslib.DNSQuestion(query, qtype=qtype))
        query_data = query.pack()
        sock_family = socket.AF_INET6 if ':' in dnsserver else socket.AF_INET
        sock = socket.socket(sock_family)
        rfile = None
        try:
            sock.settimeout(timeout or None)
            sock.connect(parse_hostport(dnsserver, 53))
            sock.send(struct.pack('>h', len(query_data)) + query_data)
            rfile = sock.makefile('r', 1024)
            reply_data_length = rfile.read(2)
            if len(reply_data_length) < 2:
                raise socket.gaierror(11004, 'getaddrinfo %r from %r failed' % (query, dnsserver))
            reply_data = rfile.read(struct.unpack('>h', reply_data_length)[0])
            record = dnslib.DNSRecord.parse(reply_data)
            iplist = [str(x.rdata) for x in record.rr if x.rtype in (1, 28, 255)]
            if any(x in blacklist for x in iplist):
                logging.debug('query=%r dnsserver=%r record bad iplist=%r', query, dnsserver, iplist)
                raise socket.gaierror(11004, 'getaddrinfo %r from %r failed' % (query, dnsserver))
            else:
                logging.debug('query=%r dnsserver=%r record iplist=%s', query, dnsserver, iplist)
                queobj.put(record)
        except socket.error as e:
            logging.debug('query=%r dnsserver=%r failed %r', query, dnsserver, e)
            queobj.put(e)
        finally:
            if rfile:
                rfile.close()
            sock.close()
    queobj = Queue.Queue()
    for dnsserver in dnsservers:
        thread.start_new_thread(do_resolve, (query, dnsserver, timeout, queobj))
    for i in range(len(dnsservers)):
        try:
            result = queobj.get(timeout)
        except Queue.Empty:
            raise socket.gaierror(11004, 'getaddrinfo %r from %r failed' % (query, dnsservers))
        if result and not isinstance(result, Exception):
            return result
        elif i == len(dnsservers) - 1:
            logging.warning('dnslib_resolve_over_tcp %r with %s return %r', query, dnsservers, result)
    raise socket.gaierror(11004, 'getaddrinfo %r from %r failed' % (query, dnsservers))


def dnslib_record2iplist(record):
    """convert dnslib.DNSRecord to iplist"""
    assert isinstance(record, dnslib.DNSRecord)
    iplist = [x for x in (str(r.rdata) for r in record.rr) if re.match(r'^\d+\.\d+\.\d+\.\d+$', x) or ':' in x]
    return iplist


def get_dnsserver_list():
    if os.name == 'nt':
        import ctypes, ctypes.wintypes, struct, socket
        DNS_CONFIG_DNS_SERVER_LIST = 6
        buf = ctypes.create_string_buffer(2048)
        ctypes.windll.dnsapi.DnsQueryConfig(DNS_CONFIG_DNS_SERVER_LIST, 0, None, None, ctypes.byref(buf), ctypes.byref(ctypes.wintypes.DWORD(len(buf))))
        ipcount = struct.unpack('I', buf[0:4])[0]
        iplist = [socket.inet_ntoa(buf[i:i+4]) for i in xrange(4, ipcount*4+4, 4)]
        return iplist
    elif os.path.isfile('/etc/resolv.conf'):
        with open('/etc/resolv.conf', 'rb') as fp:
            return re.findall(r'(?m)^nameserver\s+(\S+)', fp.read())
    else:
        logging.warning("get_dnsserver_list failed: unsupport platform '%s-%s'", sys.platform, os.name)
        return []


def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        __import__('time').sleep(seconds)
        return target(*args, **kwargs)
    return __import__('thread').start_new_thread(wrap, args, kwargs)


def is_clienthello(data):
    if len(data) < 20:
        return False
    if data.startswith('\x16\x03'):
        # TLSv12/TLSv11/TLSv1/SSLv3
        length, = struct.unpack('>h', data[3:5])
        return len(data) == 5 + length
    elif data[0] == '\x80' and data[2:4] == '\x01\x03':
        # SSLv23
        return len(data) == 2 + ord(data[1])
    else:
        return False


def extract_sni_name(packet):
    if packet.startswith('\x16\x03'):
        stream = io.BytesIO(packet)
        stream.read(0x2b)
        session_id_length = ord(stream.read(1))
        stream.read(session_id_length)
        cipher_suites_length, = struct.unpack('>h', stream.read(2))
        stream.read(cipher_suites_length+2)
        extensions_length, = struct.unpack('>h', stream.read(2))
        extensions = {}
        while True:
            data = stream.read(2)
            if not data:
                break
            etype, = struct.unpack('>h', data)
            elen, = struct.unpack('>h', stream.read(2))
            edata = stream.read(elen)
            if etype == 0:
                server_name = edata[5:]
                return server_name


class URLFetch(object):
    """URLFetch for gae/php fetchservers"""
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations', 'Connection', 'Cache-Control'])

    def __init__(self, handler, fetchserver):
        assert isinstance(fetchserver, basestring) and callable(create_http_request)
        self.handler = handler
        self.fetchserver = fetchserver
        self.create_http_request = handler.create_http_request

    def fetch(self, method, url, headers, body, timeout, **kwargs):
        return self.__google_fetch(method, url, headers, body, timeout, **kwargs)

    def __google_fetch(self, method, url, headers, body, timeout, **kwargs):
        url = url.replace('http://', 'https://', 1)
        url = re.sub(r'^(\w+://)', r'\g<1>2-ps.googleusercontent.com/h/', url)
        #print url
        proxies = {'http':'%s:%s'%('127.0.0.1', common.LISTEN_PORT),'https':'%s:%s'%('127.0.0.1', common.LISTEN_PORT)}
        opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
        response = opener.open(url)
        #print response
        return response



class BaseProxyHandlerFilter(object):
    """base proxy handler filter"""
    def filter(self, handler):
        raise NotImplementedError


class SimpleProxyHandlerFilter(BaseProxyHandlerFilter):
    """simple proxy handler filter"""
    def filter(self, handler):
        if handler.command == 'CONNECT':
            return [handler.FORWARD, handler.host, handler.port, handler.connect_timeout]
        else:
            return [handler.DIRECT, {}]

class SimpleProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """SimpleProxyHandler for GoAgent 3.x"""

    protocol_version = 'HTTP/1.1'
    ssl_version = ssl.PROTOCOL_SSLv23
    disable_transport_ssl = True
    scheme = 'http'
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations', 'Connection', 'Cache-Control'])
    bufsize = 256 * 1024
    max_timeout = 4
    connect_timeout = 4
    first_run_lock = threading.Lock()
    handler_filters = [SimpleProxyHandlerFilter()]
    sticky_filter = None

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            BaseHTTPServer.BaseHTTPRequestHandler.finish(self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write('%s %d %s\r\n' % (self.protocol_version, code, message))

    def send_header(self, keyword, value):
        """Send a MIME header."""
        base_send_header = BaseHTTPServer.BaseHTTPRequestHandler.send_header
        keyword = keyword.title()
        if keyword == 'Set-Cookie':
            for cookie in re.split(r', (?=[^ =]+(?:=|$))', value):
                base_send_header(self, keyword, cookie)
        elif keyword == 'Content-Disposition' and '"' not in value:
            value = re.sub(r'filename=([^"\']+)', 'filename="\\1"', value)
            base_send_header(self, keyword, value)
        else:
            base_send_header(self, keyword, value)

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except StandardError as e:
                logging.exception('%s.first_run() return %r', self.__class__, e)
        self.__class__.setup = BaseHTTPServer.BaseHTTPRequestHandler.setup
        self.__class__.do_CONNECT = self.__class__.do_METHOD
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.setup()

    def handle_one_request(self):
        if not self.disable_transport_ssl and self.scheme == 'http':
            leadbyte = self.connection.recv(1, socket.MSG_PEEK)
            if leadbyte in ('\x80', '\x16'):
                server_name = ''
                if leadbyte == '\x16':
                    for _ in xrange(2):
                        leaddata = self.connection.recv(1024, socket.MSG_PEEK)
                        if is_clienthello(leaddata):
                            try:
                                server_name = extract_sni_name(leaddata)
                            finally:
                                break
                try:
                    certfile = CertUtil.get_cert(server_name or 'www.google.com')
                    ssl_sock = ssl.wrap_socket(self.connection, ssl_version=self.ssl_version, keyfile=certfile, certfile=certfile, server_side=True)
                except StandardError as e:
                    if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                        logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
                    return
                self.connection = ssl_sock
                self.rfile = self.connection.makefile('rb', self.bufsize)
                self.wfile = self.connection.makefile('wb', 0)
                self.scheme = 'https'
        return BaseHTTPServer.BaseHTTPRequestHandler.handle_one_request(self)

    def first_run(self):
        pass

    def gethostbyname2(self, hostname):
        return socket.gethostbyname_ex(hostname)[-1]

    def create_tcp_connection(self, hostname, port, timeout, **kwargs):
        return socket.create_connection((hostname, port), timeout)

    def create_ssl_connection(self, hostname, port, timeout, **kwargs):
        sock = self.create_tcp_connection(hostname, port, timeout, **kwargs)
        ssl_sock = ssl.wrap_socket(sock, ssl_version=self.ssl_version)
        return ssl_sock

    def create_http_request(self, method, url, headers, body, timeout, **kwargs):
        scheme, netloc, path, query, _ = urlparse.urlsplit(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query
        if 'Host' not in headers:
            headers['Host'] = host
        if body and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(body))
        ConnectionType = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
        connection = ConnectionType(netloc, timeout=timeout)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response

    def create_http_request_withserver(self, fetchserver, method, url, headers, body, timeout, **kwargs):
        return URLFetch(self, fetchserver).fetch(method, url, headers, body, timeout, **kwargs)

    def handle_urlfetch_error(self, fetchserver, response):
        pass

    def handle_urlfetch_response_close(self, fetchserver, response):
        pass

    def parse_header(self):
        if self.command == 'CONNECT':
            netloc = self.path
        elif self.path[0] == '/':
            netloc = self.headers.get('Host', 'localhost')
            self.path = '%s://%s%s' % (self.scheme, netloc, self.path)
        else:
            netloc = urlparse.urlsplit(self.path).netloc
        m = re.match(r'^(.+):(\d+)$', netloc)
        if m:
            self.host = m.group(1).strip('[]')
            self.port = int(m.group(2))
        else:
            self.host = netloc
            self.port = 443 if self.scheme == 'https' else 80

    def forward_socket(self, local, remote, timeout):
        try:
            tick = 1
            bufsize = self.bufsize
            timecount = timeout
            while 1:
                timecount -= tick
                if timecount <= 0:
                    break
                (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
                if errors:
                    break
                for sock in ins:
                    data = sock.recv(bufsize)
                    if not data:
                        break
                    if sock is remote:
                        local.sendall(data)
                        timecount = timeout
                    else:
                        remote.sendall(data)
                        timecount = timeout
        except socket.timeout:
            pass
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
            if e.args[0] in (errno.EBADF,):
                return
        finally:
            for sock in (remote, local):
                try:
                    sock.close()
                except StandardError:
                    pass

    def MOCK(self, status, headers, content):
        """mock response"""
        logging.info('%s "MOCK %s %s %s" %d %d', self.address_string(), self.command, self.path, self.protocol_version, status, len(content))
        headers = dict((k.title(), v) for k, v in headers.items())
        if 'Transfer-Encoding' in headers:
            del headers['Transfer-Encoding']
        if 'Content-Length' not in headers:
            headers['Content-Length'] = len(content)
        if 'Connection' not in headers:
            headers['Connection'] = 'close'
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def STRIP(self, do_ssl_handshake=True, sticky_filter=None):
        """strip connect"""
        certfile = CertUtil.get_cert(self.host)
        logging.info('%s "STRIP %s %s:%d %s" - -', self.address_string(), self.command, self.host, self.port, self.protocol_version)
        self.send_response(200)
        self.end_headers()
        if do_ssl_handshake:
            try:
                ssl_sock = ssl.wrap_socket(self.connection, ssl_version=self.ssl_version, keyfile=certfile, certfile=certfile, server_side=True)
            except StandardError as e:
                if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                    logging.exception('ssl.wrap_socket(self.connection=%r) failed: %s', self.connection, e)
                return
            self.connection = ssl_sock
            self.rfile = self.connection.makefile('rb', self.bufsize)
            self.wfile = self.connection.makefile('wb', 0)
            self.scheme = 'https'
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise
        self.sticky_filter = sticky_filter
        try:
            self.do_METHOD()
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ETIMEDOUT, errno.EPIPE):
                raise

    def FORWARD(self, hostname, port, timeout, kwargs={}):
        """forward socket"""
        do_ssl_handshake = kwargs.pop('do_ssl_handshake', False)
        local = self.connection
        remote = None
        self.send_response(200)
        self.end_headers()
        self.close_connection = 1
        data = local.recv(1024)
        if not data:
            local.close()
            return
        data_is_clienthello = is_clienthello(data)
        if data_is_clienthello:
            kwargs['client_hello'] = data
        max_retry = kwargs.get('max_retry', 5)
        for i in xrange(max_retry):
            try:
                if do_ssl_handshake:
                    remote = self.create_ssl_connection(hostname, port, timeout, **kwargs)
                else:
                    remote = self.create_tcp_connection(hostname, port, timeout, **kwargs)
                if not data_is_clienthello and remote and not isinstance(remote, Exception):
                    remote.sendall(data)
                break
            except StandardError as e:
                logging.exception('%s "FWD %s %s:%d %s" %r', self.address_string(), self.command, hostname, port, self.protocol_version, e)
                if hasattr(remote, 'close'):
                    remote.close()
                if i == max_retry - 1:
                    raise
        logging.info('%s "FWD %s %s:%d %s" - -', self.address_string(), self.command, hostname, port, self.protocol_version)
        if hasattr(remote, 'fileno'):
            # reset timeout default to avoid long http upload failure, but it will delay timeout retry :(
            remote.settimeout(None)
        del kwargs
        data = data_is_clienthello and getattr(remote, 'data', None)
        if data:
            del remote.data
            local.sendall(data)
        self.forward_socket(local, remote, self.max_timeout)

    def DIRECT(self, kwargs):
        method = self.command
        if 'url' in kwargs:
            url = kwargs.pop('url')
        elif self.path.lower().startswith(('http://', 'https://', 'ftp://')):
            url = self.path
        else:
            url = 'http://%s%s' % (self.headers['Host'], self.path)
        headers = dict((k.title(), v) for k, v in self.headers.items())
        body = self.body
        response = None
        try:
            response = self.create_http_request(method, url, headers, body, timeout=self.connect_timeout, **kwargs)
            logging.info('%s "DIRECT %s %s %s" %s %s', self.address_string(), self.command, url, self.protocol_version, response.status, response.getheader('Content-Length', '-'))
            response_headers = dict((k.title(), v) for k, v in response.getheaders())
            self.send_response(response.status)
            for key, value in response.getheaders():
                self.send_header(key, value)
            self.end_headers()
            if self.command == 'HEAD' or response.status in (204, 304):
                response.close()
                return
            need_chunked = 'Transfer-Encoding' in response_headers
            while True:
                data = response.read(8192)
                if not data:
                    if need_chunked:
                        self.wfile.write('0\r\n\r\n')
                    break
                if need_chunked:
                    self.wfile.write('%x\r\n' % len(data))
                self.wfile.write(data)
                if need_chunked:
                    self.wfile.write('\r\n')
                del data
        except (ssl.SSLError, socket.timeout, socket.error):
            if response:
                if response.fp and response.fp._sock:
                    response.fp._sock.close()
                response.close()
        finally:
            if response:
                response.close()

    def URLFETCH(self, fetchservers, max_retry=5, kwargs={}):
        """urlfetch from fetchserver"""
        method = self.command
        if self.path[0] == '/':
            url = '%s://%s%s' % (self.scheme, self.headers['Host'], self.path)
        elif self.path.lower().startswith(('http://', 'https://', 'ftp://')):
            url = self.path
        else:
            raise ValueError('URLFETCH %r is not a valid url' % self.path)
        headers = dict((k.title(), v) for k, v in self.headers.items())
        body = self.body
        response = None
        errors = []
        fetchserver = ''
        for i in xrange(max_retry):
            try:
                response = self.create_http_request_withserver(fetchserver, method, url, headers, body, timeout=60, **kwargs)
                if response:
                    break
            except StandardError as e:
                errors.append(e)
                logging.info('URLFETCH "%s %s" fetchserver=%r %r, retry...', method, url, fetchserver, e)
        #logging.info('%s "URL %s %s %s" %s %s', self.address_string(), method, url, self.protocol_version, response.status, response.getheader('Content-Length', '-'))
        try:
            bufsize = 8192
            while True:
                data = response.read(bufsize)
                if data:
                    self.wfile.write(data)
                    #print 'read'
                if not data:
                    self.handle_urlfetch_response_close(fetchserver, response)
                    response.close()
                    break
                del data
        except NetWorkIOError as e:
            if e[0] in (errno.ECONNABORTED, errno.EPIPE) or 'bad write retry' in repr(e):
                return

    def do_METHOD(self):
        self.parse_header()
        self.body = self.rfile.read(int(self.headers['Content-Length'])) if 'Content-Length' in self.headers else ''
        if self.sticky_filter:
            action = self.sticky_filter.filter(self)
            if action:
                return action.pop(0)(*action)
        for handler_filter in self.handler_filters:
            action = handler_filter.filter(self)
            if action:
                return action.pop(0)(*action)


class AdvancedProxyHandler(SimpleProxyHandler):
    """Advanced Proxy Handler"""
    dns_cache = LRUCache(64*1024)
    dns_servers = []
    dns_blacklist = []
    tcp_connection_time = collections.defaultdict(float)
    tcp_connection_time_with_clienthello = collections.defaultdict(float)
    tcp_connection_cache = collections.defaultdict(Queue.PriorityQueue)
    ssl_connection_time = collections.defaultdict(float)
    ssl_connection_cache = collections.defaultdict(Queue.PriorityQueue)
    ssl_connection_good_ipaddrs = {}
    ssl_connection_bad_ipaddrs = {}
    ssl_connection_unknown_ipaddrs = {}
    ssl_connection_keepalive = False
    max_window = 4
    openssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)

    def gethostbyname2(self, hostname):
        try:
            iplist = self.dns_cache[hostname]
        except KeyError:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) or ':' in hostname:
                iplist = [hostname]
            elif self.dns_servers:
                try:
                    record = dnslib_resolve_over_udp(hostname, self.dns_servers, timeout=2, blacklist=self.dns_blacklist)
                except socket.gaierror:
                    record = dnslib_resolve_over_tcp(hostname, self.dns_servers, timeout=2, blacklist=self.dns_blacklist)
                iplist = dnslib_record2iplist(record)
            else:
                iplist = socket.gethostbyname_ex(hostname)[-1]
            self.dns_cache[hostname] = iplist
        return iplist

    def create_tcp_connection(self, hostname, port, timeout, **kwargs):
        client_hello = kwargs.get('client_hello', None)
        cache_key = kwargs.get('cache_key') if not client_hello else None
        def create_connection(ipaddr, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable nagle algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(min(self.connect_timeout, timeout))
                # start connection time record
                start_time = time.time()
                # TCP connect
                sock.connect(ipaddr)
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = time.time() - start_time
                # send client hello and peek server hello
                if client_hello:
                    sock.sendall(client_hello)
                    if gevent and isinstance(sock, gevent.socket.socket):
                        sock.data = data = sock.recv(4096)
                    else:
                        data = sock.recv(4096, socket.MSG_PEEK)
                    if not data:
                        logging.debug('create_tcp_connection %r with client_hello return NULL byte, continue %r', ipaddr, time.time()-start_time)
                        raise socket.timeout('timed out')
                    # record TCP connection time with client hello
                    self.tcp_connection_time_with_clienthello[ipaddr] = time.time() - start_time
                # set timeout
                sock.settimeout(timeout)
                # put tcp socket object to output queobj
                queobj.put(sock)
            except (socket.error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.tcp_connection_time[ipaddr] = self.connect_timeout+random.random()
                # close tcp socket
                if sock:
                    sock.close()
        def close_connection(count, queobj, first_tcp_time):
            for _ in range(count):
                sock = queobj.get()
                tcp_time_threshold = min(1, 1.3 * first_tcp_time)
                if sock and not isinstance(sock, Exception):
                    ipaddr = sock.getpeername()
                    if cache_key and self.tcp_connection_time[ipaddr] < tcp_time_threshold:
                        cache_queue = self.tcp_connection_cache[cache_key]
                        if cache_queue.qsize() < 8:
                            try:
                                _, old_sock = cache_queue.get_nowait()
                                old_sock.close()
                            except Queue.Empty:
                                pass
                        cache_queue.put((time.time(), sock))
                    else:
                        sock.close()
        try:
            while cache_key:
                ctime, sock = self.tcp_connection_cache[cache_key].get_nowait()
                if time.time() - ctime < 30:
                    return sock
                else:
                    sock.close()
        except Queue.Empty:
            pass
        addresses = [(x, port) for x in self.gethostbyname2(hostname)]
        sock = None
        for _ in range(kwargs.get('max_retry', 5)):
            window = min((self.max_window+1)//2, len(addresses))
            if client_hello:
                addresses.sort(key=self.tcp_connection_time_with_clienthello.__getitem__)
            else:
                addresses.sort(key=self.tcp_connection_time.__getitem__)
            addrs = addresses[:window] + random.sample(addresses, window)
            queobj = gevent.queue.Queue() if gevent else Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                sock = queobj.get()
                if not isinstance(sock, Exception):
                    first_tcp_time = self.tcp_connection_time[sock.getpeername()] if not cache_key else 0
                    thread.start_new_thread(close_connection, (len(addrs)-i-1, queobj, first_tcp_time))
                    return sock
                elif i == 0:
                    # only output first error
                    logging.warning('create_tcp_connection to %r with %s return %r, try again.', hostname, addrs, sock)
        if isinstance(sock, Exception):
            raise sock

    def create_ssl_connection(self, hostname, port, timeout, **kwargs):
        cache_key = kwargs.get('cache_key')
        validate = kwargs.get('validate')
        def create_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(min(self.connect_timeout, timeout))
                # pick up the certificate
                if not validate:
                    ssl_sock = ssl.wrap_socket(sock, ssl_version=self.ssl_version, do_handshake_on_connect=False)
                else:
                    ssl_sock = ssl.wrap_socket(sock, ssl_version=self.ssl_version, cert_reqs=ssl.CERT_REQUIRED, ca_certs=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem'), do_handshake_on_connect=False)
                ssl_sock.settimeout(min(self.connect_timeout, timeout))
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                ssl_sock.ssl_time = connected_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # remove from bad ipaddrs dict
                self.ssl_connection_bad_ipaddrs.pop(ipaddr, None)
                # add to good ipaddrs dict
                if ipaddr not in self.ssl_connection_good_ipaddrs:
                    self.ssl_connection_good_ipaddrs[ipaddr] = handshaked_time
                # verify SSL certificate.
                if validate and hostname.endswith('.appspot.com'):
                    cert = ssl_sock.getpeercert()
                    orgname = next((v for ((k, v),) in cert['subject'] if k == 'organizationName'))
                    if not orgname.lower().startswith('google '):
                        raise ssl.SSLError("%r certificate organizationName(%r) not startswith 'Google'" % (hostname, orgname))
                # set timeout
                ssl_sock.settimeout(timeout)
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, ssl.SSLError, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.connect_timeout + random.random()
                # add to bad ipaddrs dict
                if ipaddr not in self.ssl_connection_bad_ipaddrs:
                    self.ssl_connection_bad_ipaddrs[ipaddr] = time.time()
                # remove from good ipaddrs dict
                self.ssl_connection_good_ipaddrs.pop(ipaddr, None)
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def create_connection_withopenssl(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.connect_timeout)
                # pick up the certificate
                server_hostname = b'mail.google.com' if hostname.endswith('.appspot.com') else None
                ssl_sock = SSLConnection(self.openssl_context, sock)
                ssl_sock.set_connect_state()
                if server_hostname and hasattr(ssl_sock, 'set_tlsext_host_name'):
                    ssl_sock.set_tlsext_host_name(server_hostname)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # remove from bad ipaddrs dict
                self.ssl_connection_bad_ipaddrs.pop(ipaddr, None)
                # add to good ipaddrs dict
                if ipaddr not in self.ssl_connection_good_ipaddrs:
                    self.ssl_connection_good_ipaddrs[ipaddr] = handshaked_time
                # verify SSL certificate.
                if validate and hostname.endswith('.appspot.com'):
                    cert = ssl_sock.get_peer_certificate()
                    commonname = next((v for k, v in cert.get_subject().get_components() if k == 'CN'))
                    if '.google' not in commonname and not commonname.endswith('.appspot.com'):
                        raise socket.error("Host name '%s' doesn't match certificate host '%s'" % (hostname, commonname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except (socket.error, OpenSSL.SSL.Error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.connect_timeout + random.random()
                # add to bad ipaddrs dict
                if ipaddr not in self.ssl_connection_bad_ipaddrs:
                    self.ssl_connection_bad_ipaddrs[ipaddr] = time.time()
                # remove from good ipaddrs dict
                self.ssl_connection_good_ipaddrs.pop(ipaddr, None)
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()
        def close_connection(count, queobj, first_tcp_time, first_ssl_time):
            for _ in range(count):
                sock = queobj.get()
                ssl_time_threshold = min(1, 1.3 * first_ssl_time)
                if sock and not isinstance(sock, Exception):
                    if cache_key and sock.ssl_time < ssl_time_threshold:
                        cache_queue = self.ssl_connection_cache[cache_key]
                        if cache_queue.qsize() < 8:
                            try:
                                _, old_sock = cache_queue.get_nowait()
                                old_sock.close()
                            except Queue.Empty:
                                pass
                        cache_queue.put((time.time(), sock))
                    else:
                        sock.close()
        def reorg_ipaddrs():
            current_time = time.time()
            for ipaddr, ctime in self.ssl_connection_good_ipaddrs.items():
                if current_time - ctime > 5 * 60:
                    self.ssl_connection_good_ipaddrs.pop(ipaddr, None)
                    self.ssl_connection_unknown_ipaddrs[ipaddr] = ctime
            for ipaddr, ctime in self.ssl_connection_bad_ipaddrs.items():
                if current_time - ctime > 5 * 60:
                    self.ssl_connection_bad_ipaddrs.pop(ipaddr, None)
                    self.ssl_connection_unknown_ipaddrs[ipaddr] = ctime
            logging.info("good_ipaddrs=%d, bad_ipaddrs=%d, unkown_ipaddrs=%d", len(self.ssl_connection_good_ipaddrs), len(self.ssl_connection_bad_ipaddrs), len(self.ssl_connection_unknown_ipaddrs))
        try:
            while cache_key:
                ctime, sock = self.ssl_connection_cache[cache_key].get_nowait()
                if time.time() - ctime < 30:
                    return sock
                else:
                    sock.close()
        except Queue.Empty:
            pass
        addresses = [(x, port) for x in self.gethostbyname2(hostname)]
        sock = None
        for i in range(kwargs.get('max_retry', 10)):
            window = self.max_window + i
            good_addrs = [x for x in addresses if x in self.ssl_connection_good_ipaddrs]
            if len(good_addrs) > window:
                good_addrs = sorted(good_addrs, key=self.ssl_connection_time.get)[:window]
            unkown_ipaddrs = [x for x in addresses if x not in self.ssl_connection_good_ipaddrs and x not in self.ssl_connection_bad_ipaddrs]
            if len(unkown_ipaddrs) > window:
                random.shuffle(unkown_ipaddrs)
                unkown_ipaddrs = unkown_ipaddrs[:window]
            bad_ipaddrs = [x for x in addresses if x in self.ssl_connection_bad_ipaddrs]
            if len(bad_ipaddrs) > window:
                bad_ipaddrs = sorted(bad_ipaddrs, key=self.ssl_connection_bad_ipaddrs.get)[:max(window, 3*window-len(good_addrs)-len(unkown_ipaddrs))]
            addrs = good_addrs + bad_ipaddrs + unkown_ipaddrs
            queobj = gevent.queue.Queue() if gevent else Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(create_connection_withopenssl, (addr, timeout, queobj))
            for i in range(len(addrs)):
                sock = queobj.get()
                if not isinstance(sock, Exception):
                    thread.start_new_thread(close_connection, (len(addrs)-i-1, queobj, sock.tcp_time, sock.ssl_time))
                    return sock
                elif i == 0:
                    # only output first error
                    logging.warning('create_ssl_connection to %r with %s return %r, try again.', hostname, addrs, sock)
            reorg_ipaddrs()
        if isinstance(sock, Exception):
            raise sock

    def create_http_request(self, method, url, headers, body, timeout, max_retry=5, bufsize=8192, crlf=None, validate=None, cache_key=None):
        scheme, netloc, path, query, _ = urlparse.urlsplit(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query
        if 'Host' not in headers:
            headers['Host'] = host
        if body and 'Content-Length' not in headers:
            headers['Content-Length'] = str(len(body))
        sock = None
        for i in range(max_retry):
            try:
                create_connection = self.create_ssl_connection if scheme == 'https' else self.create_tcp_connection
                sock = create_connection(host, port, timeout, validate=validate, cache_key=cache_key)
                break
            except StandardError as e:
                logging.exception('create_http_request "%s %s" failed:%s', method, url, e)
                if sock:
                    sock.close()
                if i == max_retry - 1:
                    raise
        request_data = ''
        crlf_counter = 0
        if scheme != 'https' and crlf:
            fakeheaders = dict((k.title(), v) for k, v in headers.items())
            fakeheaders.pop('Content-Length', None)
            fakeheaders.pop('Cookie', None)
            fakeheaders.pop('Host', None)
            if 'User-Agent' not in fakeheaders:
                fakeheaders['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1878.0 Safari/537.36'
            if 'Accept-Language' not in fakeheaders:
                fakeheaders['Accept-Language'] = 'zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4'
            if 'Accept' not in fakeheaders:
                fakeheaders['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            fakeheaders_data = ''.join('%s: %s\r\n' % (k, v) for k, v in fakeheaders.items() if k not in self.skip_headers)
            while crlf_counter < 5 or len(request_data) < 1500 * 2:
                request_data += 'GET / HTTP/1.1\r\n%s\r\n' % fakeheaders_data
                crlf_counter += 1
            request_data += '\r\n\r\n\r\n'
        request_data += '%s %s %s\r\n' % (method, path, self.protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k.title(), v) for k, v in headers.items() if k.title() not in self.skip_headers)
        request_data += '\r\n'
        if isinstance(body, bytes):
            sock.sendall(request_data.encode() + body)
        elif hasattr(body, 'read'):
            sock.sendall(request_data)
            while 1:
                data = body.read(bufsize)
                if not data:
                    break
                sock.sendall(data)
        else:
            raise TypeError('create_http_request(body) must be a string or buffer, not %r' % type(body))
        response = None
        try:
            while crlf_counter:
                if sys.version[:3] == '2.7':
                    response = httplib.HTTPResponse(sock, buffering=False)
                else:
                    response = httplib.HTTPResponse(sock)
                    response.fp.close()
                    response.fp = sock.makefile('rb', 0)
                response.begin()
                response.read()
                response.close()
                crlf_counter -= 1
        except StandardError as e:
            logging.exception('crlf skip read host=%r path=%r error: %r', headers.get('Host'), path, e)
            if response:
                if response.fp and response.fp._sock:
                    response.fp._sock.close()
                response.close()
            if sock:
                sock.close()
            return None
        if sys.version[:3] == '2.7':
            response = httplib.HTTPResponse(sock, buffering=True)
        else:
            response = httplib.HTTPResponse(sock)
            response.fp.close()
            response.fp = sock.makefile('rb')
        response.begin()
        if self.ssl_connection_keepalive and scheme == 'https' and cache_key:
            response.cache_key = cache_key
            response.cache_sock = response.fp._sock
        return response

    def handle_urlfetch_response_close(self, fetchserver, response):
        cache_sock = getattr(response, 'cache_sock', None)
        if cache_sock:
            if self.scheme == 'https':
                self.ssl_connection_cache[response.cache_key].put((time.time(), cache_sock))
            else:
                cache_sock.close()
            del response.cache_sock

    def handle_urlfetch_error(self, fetchserver, response):
        pass



class Common(object):
    """Global Config Object"""

    ENV_CONFIG_PREFIX = 'GOAGENT_'

    def __init__(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG_FILENAME = os.path.splitext(os.path.abspath(__file__))[0]+'.ini'
        self.CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', self.CONFIG_FILENAME)
        self.CONFIG_MY_FILENAME = re.sub(r'\.ini$', '.my.ini', self.CONFIG_FILENAME)
        self.CONFIG.read([self.CONFIG_FILENAME, self.CONFIG_USER_FILENAME, self.CONFIG_MY_FILENAME])

        for key, value in os.environ.items():
            m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % self.ENV_CONFIG_PREFIX, key)
            if m:
                self.CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_USERNAME = self.CONFIG.get('listen', 'username') if self.CONFIG.has_option('listen', 'username') else ''
        self.LISTEN_PASSWORD = self.CONFIG.get('listen', 'password') if self.CONFIG.has_option('listen', 'password') else ''
        self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo')

        self.GAE_MODE = self.CONFIG.get('gae', 'mode')
        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile').strip()
        self.GAE_WINDOW = self.CONFIG.getint('gae', 'window')
        self.GAE_KEEPALIVE = self.CONFIG.getint('gae', 'keepalive') if self.CONFIG.has_option('gae', 'keepalive') else 0
        self.GAE_SSLVERSION = self.CONFIG.get('gae', 'sslversion')

        if self.GAE_PROFILE == 'auto':
            try:
                socket.create_connection(('2001:4860:4860::8888', 53), timeout=1).close()
                logging.info('Use profile ipv6')
                self.GAE_PROFILE = 'ipv6'
            except socket.error as e:
                logging.info('Fail try profile ipv6 %r, fallback ipv4', e)
                self.GAE_PROFILE = 'ipv4'
        hosts_section, http_section = '%s/hosts' % self.GAE_PROFILE, '%s/http' % self.GAE_PROFILE

        if 'USERDNSDOMAIN' in os.environ and re.match(r'^\w+\.\w+$', os.environ['USERDNSDOMAIN']):
            self.CONFIG.set(hosts_section, '.' + os.environ['USERDNSDOMAIN'], '')

        self.HOST_MAP = collections.OrderedDict((k, v or k) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and not k.startswith('.'))
        self.HOST_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and k.startswith('.'))
        self.HOST_POSTFIX_ENDSWITH = tuple(self.HOST_POSTFIX_MAP)

        self.HOSTPORT_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and not k.startswith('.'))
        self.HOSTPORT_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in self.CONFIG.items(hosts_section) if ':' in k and k.startswith('.'))
        self.HOSTPORT_POSTFIX_ENDSWITH = tuple(self.HOSTPORT_POSTFIX_MAP)

        self.URLRE_MAP = collections.OrderedDict((re.compile(k).match, v) for k, v in self.CONFIG.items(hosts_section) if '\\' in k)


        self.IPLIST_MAP = collections.OrderedDict((k, v.split('|')) for k, v in self.CONFIG.items('iplist'))
        self.IPLIST_MAP.update((k, [k]) for k, v in self.HOST_MAP.items() if k == v)

        self.FETCHMAX_LOCAL = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER = self.CONFIG.get('fetchmax', 'server')

        self.DNS_ENABLE = self.CONFIG.getint('dns', 'enable')
        self.DNS_LISTEN = self.CONFIG.get('dns', 'listen')
        self.DNS_SERVERS = self.CONFIG.get('dns', 'servers').split('|')
        self.DNS_BLACKLIST = set(self.CONFIG.get('dns', 'blacklist').split('|'))
        self.DNS_TCPOVER = tuple(self.CONFIG.get('dns', 'tcpover').split('|')) if self.CONFIG.get('dns', 'tcpover').strip() else tuple()

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')
        
    def resolve_iplist(self):
        def do_resolve(host, dnsservers, queue):
            iplist = []
            for dnslib_resolve in (dnslib_resolve_over_tcp,):
                try:
                    iplist += dnslib_record2iplist(dnslib_resolve_over_udp(host, dnsservers, timeout=4, blacklist=self.DNS_BLACKLIST))
                except (socket.error, OSError) as e:
                    logging.debug('%r remote host=%r failed: %s', dnslib_resolve, host, e)
            queue.put((host, dnsservers, iplist))
        # https://support.google.com/websearch/answer/186669?hl=zh-Hans
        google_blacklist = ['216.239.32.20'] + list(self.DNS_BLACKLIST)
        for name, need_resolve_hosts in list(self.IPLIST_MAP.items()):
            if all(re.match(r'\d+\.\d+\.\d+\.\d+', x) or ':' in x for x in need_resolve_hosts):
                continue
            need_resolve_remote = [x for x in need_resolve_hosts if ':' not in x and not re.match(r'\d+\.\d+\.\d+\.\d+', x)]
            resolved_iplist = [x for x in need_resolve_hosts if x not in need_resolve_remote]
            result_queue = Queue.Queue()
            for host in need_resolve_remote:
                for dnsserver in self.DNS_SERVERS:
                    logging.debug('resolve remote host=%r from dnsserver=%r', host, dnsserver)
                    thread.start_new_thread(do_resolve, (host, [dnsserver], result_queue))
            for _ in xrange(len(self.DNS_SERVERS) * len(need_resolve_remote)):
                try:
                    host, dnsservers, iplist = result_queue.get(timeout=5)
                    resolved_iplist += iplist or []
                    logging.debug('resolve remote host=%r from dnsservers=%s return iplist=%s', host, dnsservers, iplist)
                except Queue.Empty:
                    logging.warn('resolve remote timeout, try resolve local')
                    resolved_iplist += sum([socket.gethostbyname_ex(x)[-1] for x in need_resolve_remote], [])
                    break
            if name.startswith('google_') and name not in ('google_cn', 'google_hk') and resolved_iplist:
                iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
            else:
                resolved_iplist = list(set(resolved_iplist))
            if name.startswith('google_'):
                resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
            if len(resolved_iplist) == 0:
                logging.error('resolve %s host return empty! please retry!', name)
                sys.exit(-1)
            logging.info('resolve name=%s host to iplist=%r', name, resolved_iplist)
            common.IPLIST_MAP[name] = resolved_iplist

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GreatAgent SimpleProxy Version	: %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'GOOGLE Mode        : %s\n' % self.GAE_MODE
        info += 'GOOGLE Profile     : %s\n' % self.GAE_PROFILE if self.GAE_PROFILE else ''
        info += '------------------------------------------------------\n'
        return info

common = Common()


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message From LocalProxy</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)


class LocalProxyServer(SocketServer.ThreadingTCPServer):
    """Local Proxy Server"""
    allow_reuse_address = True
    daemon_threads = True

    def close_request(self, request):
        try:
            request.close()
        except StandardError:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def handle_error(self, *args):
        """make ThreadingTCPServer happy"""
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if isinstance(error, NetWorkIOError) and len(error.args) > 1 and 'bad write retry' in error.args[1]:
            exc_info = error = None
        else:
            del exc_info, error
            SocketServer.ThreadingTCPServer.handle_error(self, *args)


class UserAgentFilter(BaseProxyHandlerFilter):
    """user agent filter"""
    def filter(self, handler):
        if common.USERAGENT_ENABLE:
            handler.headers['User-Agent'] = common.USERAGENT_STRING


class FakeHttpsFilter(BaseProxyHandlerFilter):
    """fake https filter"""
    def filter(self, handler):
        if handler.command == 'CONNECT':
            return [handler.STRIP, True, None]

class HostsFilter(BaseProxyHandlerFilter):
    """force https filter"""

    def filter(self, handler):
        host, port = handler.host, handler.port
        hostport = handler.path if handler.command == 'CONNECT' else '%s:%d' % (host, port)
        hostname = ''
        if host in common.HOST_MAP:
            hostname = common.HOST_MAP[host] or host
        elif host.endswith(common.HOST_POSTFIX_ENDSWITH):
            hostname = next(common.HOST_POSTFIX_MAP[x] for x in common.HOST_POSTFIX_MAP if host.endswith(x)) or host
            common.HOST_MAP[host] = hostname
        if hostport in common.HOSTPORT_MAP:
            hostname = common.HOSTPORT_MAP[hostport] or host
        elif hostport.endswith(common.HOSTPORT_POSTFIX_ENDSWITH):
            hostname = next(common.HOSTPORT_POSTFIX_MAP[x] for x in common.HOSTPORT_POSTFIX_MAP if hostport.endswith(x)) or host
            common.HOSTPORT_MAP[hostport] = hostname
        if handler.command != 'CONNECT' and common.URLRE_MAP:
            try:
                hostname = next(common.URLRE_MAP[x] for x in common.URLRE_MAP if x(handler.path)) or host
            except StopIteration:
                pass
        if not hostname:
            return None
        elif hostname in common.IPLIST_MAP:
            handler.dns_cache[host] = common.IPLIST_MAP[hostname]
        elif hostname == host and host.endswith(common.DNS_TCPOVER) and host not in handler.dns_cache:
            try:
                iplist = dnslib_record2iplist(dnslib_resolve_over_tcp(host, handler.dns_servers, timeout=4, blacklist=handler.dns_blacklist))
                logging.info('HostsFilter dnslib_resolve_over_tcp %r with %r return %s', host, handler.dns_servers, iplist)
                handler.dns_cache[host] = iplist
            except socket.error as e:
                logging.warning('HostsFilter dnslib_resolve_over_tcp %r with %r failed: %r', host, handler.dns_servers, e)
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname) or ':' in hostname:
            handler.dns_cache[host] = [hostname]
        cache_key = '%s:%s' % (hostname, port)
        if handler.command == 'CONNECT':
            return [handler.FORWARD, host, port, handler.connect_timeout, {'cache_key': cache_key}]
        else:
            return [handler.DIRECT, {'cache_key': cache_key}]

class GAEFetchFilter(BaseProxyHandlerFilter):
    """force https filter"""
    def filter(self, handler):
        """https://developers.google.com/appengine/docs/python/urlfetch/"""
        return [handler.URLFETCH, '', common.FETCHMAX_LOCAL, {}]


class GAEProxyHandler(AdvancedProxyHandler):
    """GAE Proxy Handler"""
    handler_filters = [UserAgentFilter(), FakeHttpsFilter(),HostsFilter(), GAEFetchFilter()]

    def first_run(self):
        """GAEProxyHandler setup, init domain/iplist map"""
        logging.info('resolve common.IPLIST_MAP names=%s to iplist', list(common.IPLIST_MAP))
        common.resolve_iplist()
                    
server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)