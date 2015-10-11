CC=cl.exe

PYTHONPATH=C:/Python27
PYTHON=$(PYTHONPATH)/python.exe

TEMPLATE_OUTPUT_PATH=..\..\pupy\payload_templates

ifndef ARCH
$(error You must specify an architecture.)
else
ifeq "$(ARCH)" "x64"
CFLAGS:=$(CFLAGS) /DWIN_X64 /D_WIN64
endif
endif

PYOBJS=_memimporter.obj MyLoadLibrary.obj Python-dynload.obj pupy_load.obj pupy.obj base_inject.obj
COMMON_OBJS=resources_bootloader_pyc.obj resources_python27_dll.obj MemoryModule.obj resources_library_compressed_string_txt.obj actctx.obj list.obj thread.obj remote_thread.obj LoadLibraryR.obj resources_msvcr90_dll.obj

all: $(TEMPLATE_OUTPUT_PATH)\pupy$(ARCH).exe $(TEMPLATE_OUTPUT_PATH)\pupy$(ARCH).dll

resources\library_compressed_string_$(ARCH).txt: gen_library_compressed_string.py
	$(PYTHON) $+
	
resources\library_compressed_string.txt: resources\library_compressed_string_$(ARCH).txt
	copy $< $@
	
resources_library_compressed_string_txt.c: gen_resource_header.py resources\library_compressed_string.txt
	$(PYTHON) $+

resources\bootloader.pyc: gen_python_bootloader.py
	$(PYTHON) $+
	
resources_bootloader_pyc.c: gen_resource_header.py resources\bootloader.pyc
	$(PYTHON) $+
	
resources\python27.dll: resources\python27_$(ARCH).dll
	copy $< $@

resources_python27_dll.c: gen_resource_header.py resources\python27.dll
	$(PYTHON) $+

resources\msvcr90.dll: resources\msvcr90_$(ARCH).dll
	copy $< $@

resources_msvcr90_dll.c: gen_resource_header.py resources\msvcr90.dll
	$(PYTHON) $+

$(PYOBJS): %.obj: %.c
	$(CC) /c $(CFLAGS) /I$(PYTHONPATH)/include $<
	
%.obj: %.c
	$(CC) /c $(CFLAGS) $<
	
ReflectiveLoader.obj: ReflectiveLoader.c
	$(CC) /c $(CFLAGS) /DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN /DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR /O2 /Ob1 $<

$(TEMPLATE_OUTPUT_PATH)\pupy$(ARCH).exe: main_exe.obj $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(CFLAGS) $+ /Fe$@

$(TEMPLATE_OUTPUT_PATH)\pupy$(ARCH).dll: main_reflective.obj $(PYOBJS) ReflectiveLoader.obj $(COMMON_OBJS)
	$(CC) $(CFLAGS) $+ /Fe$@ /LD

.PHONY: clean

ifneq "$(QUICK)" "1"
.PHONY: resources\python27.dll resources\msvcr90.dll
endif

clean:
	del *.obj
	del *.exp
	del pupy$(ARCH).exe
	del pupy$(ARCH).dll
	del resources\bootloader.pyc
	del resources\library_compressed_string.txt
	del resources\library_compressed_string_x64.txt
	del resources\library_compressed_string_x86.txt
	del resources\python27.dll
	del resources\msvcr90.dll
