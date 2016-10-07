import os
import zipfile

def zip(src, dst):

	if not os.path.exists(src):
		print "[-] The file \"%s\" does not exists" % src
		return

	isDir = False
	if os.path.isdir(src):
		isDir = True

	if not dst:
		if isDir:
			d = src.split(os.sep)
			dst = d[len(d)-1] + '.zip'
		else:
			dst = src + '.zip'

	# To not overwrite an existing file
	if os.path.exists(dst):
		print "[-] The destination file \"%s\" already exists" % dst
		return

	# Zip process
	zf = zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)
	if isDir:
		abs_src = os.path.abspath(src)
		for dirname, subdirs, files in os.walk(src):
			for filename in files:
				absname = os.path.abspath(os.path.join(dirname, filename))
				arcname = absname[len(abs_src) + 1:]
				zf.write(absname, arcname)
	else:
		zf.write(src)

	print "[+] File zipped correctly: \"%s\"" % dst
	zf.close()


def unzip(src, dst):
	
	if not os.path.exists(src):
		print "[-] The file \"%s\" does not exists" % src
		return

	if not dst:
		d = src.split(os.sep)
		dst = d[len(d)-1].replace('.zip', '')

	# To not overwrite an existing file
	if os.path.exists(dst):
		print "[-] The destination file \"%s\" already exists" % dst
		return

	if zipfile.is_zipfile(src):
		with zipfile.ZipFile(src, "r") as z:
			z.extractall(dst)
		print "[+] File unzipped correctly: \"%s\"" % dst
	else:
		print '[-] The zipped file does not have a valid zip format: \"%s\"'