del *.obj
del *.exp
del pupyx64.exe
del pupyx64.dll

::First: generate resources :
"C:\\Python27\\python.exe" gen_library_compressed_string.py
copy resources\library_compressed_string_x64.txt resources\library_compressed_string.txt
"C:\\Python27\\python.exe" gen_resource_header.py resources\library_compressed_string.txt 
copy resources\python27_x64.dll resources\python27.dll
"C:\\Python27\\python.exe" gen_resource_header.py resources\python27.dll
"C:\\Python27\\python.exe" gen_python_bootloader.py
copy resources\msvcr90_x64.dll resources\msvcr90.dll
"C:\\Python27\\python.exe" gen_resource_header.py resources\msvcr90.dll
"C:\\Python27\\python.exe" gen_resource_header.py resources\bootloader.pyc
::compile them to obj files :
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c resources_library_compressed_string_txt.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c resources_bootloader_pyc.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c resources_python27_dll.c
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\adm64\cl.exe" /c resources_msvcr90_dll.c

::then compile

"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c Python-dynload.c /IC:\Python27\include /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c MemoryModule.c /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c MyLoadLibrary.c /IC:\Python27\include /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c _memimporter.c /IC:\Python27\include /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c pupy_load.c /IC:\Python27\include /DWIN_X64 /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /O2 /Ob1 /c ReflectiveLoader.c /DWIN_X64 -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN /DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c actctx.c /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c pupy.c /IC:\Python27\include /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c LoadLibraryR.c /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c list.c /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c thread.c /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c remote_thread.c /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" /c base_inject.c /IC:\Python27\include /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" main_exe.c _memimporter.obj MyLoadLibrary.obj Python-dynload.obj resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj pupy_load.obj resources_library_compressed_string_txt.obj actctx.obj pupy.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj base_inject.obj resources_msvcr90_dll.obj /Fepupyx64.exe /D_WIN64
"C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\amd64\cl.exe" main_reflective.c _memimporter.obj MyLoadLibrary.obj Python-dynload.obj resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj pupy_load.obj ReflectiveLoader.obj resources_library_compressed_string_txt.obj actctx.obj pupy.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj base_inject.obj resources_msvcr90_dll.obj /Fepupyx64.dll /LD /D_WIN64

copy pupyx64.dll ..\..\pupy\payloads\
copy pupyx64.exe ..\..\pupy\payloads\

