version = '0.9-2'

###############################################################################

print '- exportashtml'

import os

if os.name == 'nt':
    scite = r'C:\Programme\wscite\SciTE.exe'
else:
    scite = '/iuehome/gritsch/bin/scite'

file = 'VideoCapture.py'
src = './' + file
dest = '../html/' + file + '.html'
os.system(scite + ' -open:%s -exportashtml:%s -quit:' % (src, dest))

###############################################################################

print '- fixhtmlfile'

import time, fixhtml

time.sleep(1) # allow SciTE to finish writing
fixhtml.fixhtmlfile(dest)

###############################################################################

print '- pydoc_it'

os.system(r'c:\Python22\python.exe c:\Python22\Lib\pydoc.py -w VideoCapture ')
os.system('move VideoCapture.html ..\html\ ')
os.remove('VideoCapture.pyc')

###############################################################################

print '- fixpydochtmlfile'

import string

file = '../html/VideoCapture.html'
fp = open(file)
cont = fp.read()
fp.close()
cont = string.replace(cont, '\r\n', '\n')
cont = string.replace(cont, '''<style type="text/css"><!--
TT { font-family: lucidatypewriter, lucida console, courier }
--></style>''', '''<style type="text/css"><!--
TT { font-family: courier new }
--></style>''')
cont = string.replace(cont, 'face="helvetica, arial"', 'face="verdana"')
cont = string.replace(cont, r'<a href=".">index</a><br><a href="file:///D|/home/python/vidcap/videocapture-' + version + r'/src/videocapture.py">d:\home\python\vidcap\videocapture-' + version + r'\src\videocapture.py</a>', '<a href="../index.html">index.html</a><br><a href="VideoCapture.py.html">VideoCapture.py</a>')
fp = open(file, 'wt')
fp.write(cont)
fp.close()

###############################################################################

print '- zip_it'

import zipfile

archive = zipfile.ZipFile('../VideoCapture-' + version + '.zip', 'w', zipfile.ZIP_DEFLATED)

archive.write('../LGPL.txt', 'LGPL.txt')
archive.write('../index.html', 'index.html')
archive.write('../html/logo.jpg', 'html/logo.jpg')
archive.write('../html/PythonPowered.gif', 'html/PythonPowered.gif')
archive.write('../html/VideoCapture.py.html', 'html/VideoCapture.py.html')
archive.write('../html/VideoCapture.html', 'html/VideoCapture.html')
archive.write('mkdist.py', 'src/mkdist.py')
archive.write('fixhtml.py', 'src/fixhtml.py')
archive.write('vidcap.dsp', 'src/vidcap.dsp')
archive.write('vidcap.dsw', 'src/vidcap.dsw')
archive.write('vidcapmodule.cpp', 'src/vidcapmodule.cpp')

archive.write('VideoCapture.py', 'src/VideoCapture.py')
archive.write('helvB08.png', 'src/helvB08.png')
archive.write('helvB08.pil', 'src/helvB08.pil')
archive.write('helvetica-10.png', 'src/helvetica-10.png')
archive.write('helvetica-10.pil', 'src/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python20/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python20/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python20/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python20/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python20/Lib/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python21/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python21/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python21/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python21/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python21/Lib/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python22/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python22/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python22/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python22/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python22/Lib/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python23/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python23/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python23/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python23/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python23/Lib/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python24/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python24/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python24/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python24/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python24/Lib/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python25/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python25/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python25/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python25/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python25/Lib/helvetica-10.pil')

archive.write('VideoCapture.py', 'Python26/Lib/VideoCapture.py')
archive.write('helvB08.png', 'Python26/Lib/helvB08.png')
archive.write('helvB08.pil', 'Python26/Lib/helvB08.pil')
archive.write('helvetica-10.png', 'Python26/Lib/helvetica-10.png')
archive.write('helvetica-10.pil', 'Python26/Lib/helvetica-10.pil')

archive.write('Python20/vidcap.pyd', 'Python20/DLLs/vidcap.pyd')
archive.write('Python21/vidcap.pyd', 'Python21/DLLs/vidcap.pyd')
archive.write('Python22/vidcap.pyd', 'Python22/DLLs/vidcap.pyd')
archive.write('Python23/vidcap.pyd', 'Python23/DLLs/vidcap.pyd')
archive.write('Python24/vidcap.dll', 'Python24/DLLs/vidcap.dll')
archive.write('Python25/vidcap.pyd', 'Python25/DLLs/vidcap.pyd')
archive.write('Python26/vidcap.pyd', 'Python26/DLLs/vidcap.pyd')

archive.write('../AMCAP/AMCAP.EXE', 'AMCAP/AMCAP.EXE')
archive.write('../AMCAP/AMCAP.DOC', 'AMCAP/AMCAP.DOC')

archive.write('../Examples/exa1_snapshot.py', 'Examples/exa1_snapshot.py')
archive.write('../Examples/exa2_show-possibilities.py', 'Examples/exa2_show-possibilities.py')
archive.write('../Examples/exa3_observer.py', 'Examples/exa3_observer.py')
archive.write('../Examples/displayPropertiesDev0.pyw', 'Examples/displayPropertiesDev0.pyw')
archive.write('../Examples/displayPropertiesDev1.pyw', 'Examples/displayPropertiesDev1.pyw')
archive.write('../Examples/test1.jpg', 'Examples/test1.jpg')
archive.write('../Examples/test2.jpg', 'Examples/test2.jpg')
archive.write('../Examples/test3.jpg', 'Examples/test3.jpg')
archive.write('../Examples/test4.jpg', 'Examples/test4.jpg')

archive.write('../Tools/readme.txt', 'Tools/readme.txt')

archive.write('../Tools/webcam-saver/webcam-saver.py', 'Tools/webcam-saver/webcam-saver.py')
archive.write('../Tools/webcam-saver/webcam-saver.ini', 'Tools/webcam-saver/webcam-saver.ini')

archive.write('../Tools/webcam-uploader/webcam-uploader.py', 'Tools/webcam-uploader/webcam-uploader.py')
archive.write('../Tools/webcam-uploader/webcam-uploader.ini', 'Tools/webcam-uploader/webcam-uploader.ini')
archive.write('../Tools/webcam-uploader/scpdropin.py', 'Tools/webcam-uploader/scpdropin.py')
archive.write('../Tools/webcam-uploader/template.html', 'Tools/webcam-uploader/template.html')
archive.write('../Tools/webcam-uploader/offline.jpg', 'Tools/webcam-uploader/offline.jpg')
archive.write('../Tools/webcam-uploader/offline2.jpg', 'Tools/webcam-uploader/offline2.jpg')

archive.write('../Tools/webcam-watcher/cam_form.ui', 'Tools/webcam-watcher/cam_form.ui')
archive.write('../Tools/webcam-watcher/cam_form.py', 'Tools/webcam-watcher/cam_form.py')
archive.write('../Tools/webcam-watcher/webcam-watcher.py', 'Tools/webcam-watcher/webcam-watcher.py')
archive.write('../Tools/webcam-watcher/webcam-watcher.ini', 'Tools/webcam-watcher/webcam-watcher.ini')
archive.write('../Tools/webcam-watcher/cam.png', 'Tools/webcam-watcher/cam.png')
archive.write('../Tools/webcam-watcher/cam256.ico', 'Tools/webcam-watcher/cam256.ico')
archive.write('../Tools/webcam-watcher/retrieving.png', 'Tools/webcam-watcher/retrieving.png')
archive.write('../Tools/webcam-watcher/error.png', 'Tools/webcam-watcher/error.png')
archive.write('../Tools/webcam-watcher/setup.py', 'Tools/webcam-watcher/setup.py')
archive.write('../Tools/webcam-watcher/makedist.bat', 'Tools/webcam-watcher/makedist.bat')

archive.write('../Tools/3rdParty/webcam-server/email.txt', 'Tools/3rdParty/webcam-server/email.txt')
archive.write('../Tools/3rdParty/webcam-server/webcam-server.py', 'Tools/3rdParty/webcam-server/webcam-server.py')
archive.write('../Tools/3rdParty/webcam-server/webcam-server.ini', 'Tools/3rdParty/webcam-server/webcam-server.ini')

archive.write('../Tools/3rdParty/pushserver/email.txt', 'Tools/3rdParty/pushserver/email.txt')
archive.write('../Tools/3rdParty/pushserver/server.py', 'Tools/3rdParty/pushserver/server.py')
archive.write('../Tools/3rdParty/pushserver/index.html', 'Tools/3rdParty/pushserver/index.html')
archive.write('../Tools/3rdParty/pushserver/test_push.html', 'Tools/3rdParty/pushserver/test_push.html')
archive.write('../Tools/3rdParty/pushserver/test_static.html', 'Tools/3rdParty/pushserver/test_static.html')

archive.close()
