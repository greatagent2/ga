#!/usr/bin/env python2
#-*-encoding:utf-8-*-

import os
import sys
import hashlib

def walk_dir(dir,fileinfo,topdown=True):
	for root, dirs, files in os.walk(dir, topdown):
		for name in files:
			path = os.path.join(root,name)
			md5v = sumfile(path)
			newpath = path.replace(dir,'')
			fileinfo.write(newpath + ':' + md5v + '\n')

def get_file_sha1(f):
	m = hashlib.sha1()
	while True:
		data = f.read(10240)
		if not data:
			break
		m.update(data)
	return m.hexdigest()

def sumfile(fpath):
	return get_file_sha1(open(fpath))

#获取脚本文件的当前路径
def cur_file_dir():
	#获取脚本路径
	path = sys.path[0]
	#判断为脚本文件还是py2exe编译后的文件，如果是脚本文件，则返回的是脚本的目录，如果是py2exe编译后的文件，则返回的是编译后的文件路径
	if os.path.isdir(path):
		return path
	elif os.path.isfile(path):
		return os.path.dirname(path)
#打印结果
print cur_file_dir()

def main():
	#dir = raw_input('please input the path:')
	dir = cur_file_dir()
	fileinfo = open('list3.txt','w')
	walk_dir(dir,fileinfo)

if __name__ == '__main__':
	main()