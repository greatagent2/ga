import httplib
import check_google_ip
from check_google_ip import common


conn   = None

def get(ip):
	conn = httplib.HTTPSConnection(ip, 443)
	#conn.request('GET', '/git-history/wwqgtxx-goagent2.1-/wwqgtxx-goagent2.1-/proxy.ini', headers = {@"Host": "wwqgtxx-goagent.googlecode.com"})
	#conn.request('GET', '/archive/wwqgtxx-goagent2.1-.zip', headers = {"Host": "wwqgtxx-goagent.googlecode.com"})
	conn.request('GET', '/archive/wwqgtxx-wallproxy2.1-.zip', headers = {"Host": "wwqgtxx-goagent.googlecode.com"})
	res = conn.getresponse()
	#print 'version:', res.version
	#print 'reason:', res.reason
	print 'status:', res.status
	print 'msg:', res.msg
	#print 'headers:', res.getheaders()
	#html
	print '\n' + '-' * 50 + '\n'
	return res.read()

def main(ips):
	for ip in ips:
		try:
			print 'try get update from:'+ip		   
			open("master.zip","w+b").write(get(ip))
			x = zipfile.ZipFile("master.zip")
			x.extractall()
			x.close()
			if os.path.isfile('master.zip'):
				os.remove('master.zip') 
			print 'get update from'+ip+'successful!!!'
			return
		except Exception, e:
			print e
		finally:
			if conn:
				conn.close()