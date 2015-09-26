SET python_path="C:\\Python27\\python.exe"
SET cl_path="C:\Users\me\AppData\Local\Programs\Common\Microsoft\Visual C++ for Python\9.0\VC\Bin\cl.exe"

del *.obj
del *.exp
del pupyx86.exe
del pupyx86.dll

IF [%1]==[quick] GOTO compilation
::First: generate resources :
copy resources\python27_x86.dll resources\python27.dll
%python_path% gen_library_compressed_string.py
copy resources\library_compressed_string_x86.txt resources\library_compressed_string.txt
%python_path% gen_resource_header.py resources\library_compressed_string.txt 
%python_path% gen_resource_header.py resources\python27.dll
copy resources\msvcr90_x86.dll resources\msvcr90.dll
%python_path% gen_resource_header.py resources\msvcr90.dll
%python_path% gen_python_bootloader.py
%python_path% gen_resource_header.py resources\bootloader.pyc

:compilation

%cl_path% /c resources_library_compressed_string_txt.c
%cl_path% /c resources_bootloader_pyc.c
%cl_path% /c resources_python27_dll.c
%cl_path% /c resources_msvcr90_dll.c

%cl_path% /c Python-dynload.c /IC:\Python27\include
%cl_path% /c MemoryModule.c
%cl_path% /c _memimporter.c /IC:\Python27\include
%cl_path% /c pupy_load.c /DWIN_X86 /IC:\Python27\include
%cl_path% /c MyLoadLibrary.c /IC:\Python27\include
%cl_path% /O2 /Ob1 /c ReflectiveLoader.c /DWIN_X86 -DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN /DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
%cl_path% /c actctx.c
%cl_path% /c pupy.c /IC:\Python27\include
%cl_path% /c LoadLibraryR.c
%cl_path% /c list.c
%cl_path% /c thread.c
%cl_path% /c remote_thread.c
%cl_path% /c base_inject.c /IC:\Python27\include
%cl_path% main_exe.c _memimporter.obj MyLoadLibrary.obj Python-dynload.obj resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj pupy_load.obj resources_library_compressed_string_txt.obj actctx.obj pupy.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj base_inject.obj resources_msvcr90_dll.obj /Fepupyx86.exe

%cl_path% main_reflective.c _memimporter.obj MyLoadLibrary.obj Python-dynload.obj resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj pupy_load.obj ReflectiveLoader.obj resources_library_compressed_string_txt.obj actctx.obj pupy.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj base_inject.obj resources_msvcr90_dll.obj /Fepupyx86.dll /LD
copy pupyx86.dll ..\..\pupy\payload_templates\
copy pupyx86.exe ..\..\pupy\payload_templates\

