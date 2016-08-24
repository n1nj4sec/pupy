/* **************** Python-dynload.c **************** */
#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include "Python-dynload.h"
#include "tmplibrary.h"
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "debug.h"

struct IMPORT imports[] = {
#include "import-tab.c"
	{ NULL, NULL }, /* sentinel */
};

void Py_XDECREF(PyObject *ob)
{
	static PyObject *tup;
	if (tup == NULL)
		tup = PyTuple_New(1);
	/* Let the tuple take the refcount */
	PyTuple_SetItem(tup, 0, ob);
	/* and overwrite it */
	PyTuple_SetItem(tup, 0, PyInt_FromLong(0));
}

void Py_XINCREF(PyObject *ob)
{
	if (ob)
		Py_BuildValue("O", ob);
}

typedef struct python_search {
	const char *libname;
	void *base;
} python_search_t;

int _load_python(const char *dllname, const char *bytes, size_t size)
{
	int i;
	struct IMPORT *p = imports;
	void * hmod;

	bool resolved = true;

	dprint("Trying to find python symbols in current process\n");
	for (i = 0; p->name && resolved; ++i, ++p) {
		p->proc = (void (*)()) dlsym(NULL, p->name);
		if (p->proc == NULL) {
			dprint("undefined symbol %s -> exit(-1). Fallback to built-in python\n", p->name);
			resolved = false;
		}
	}

	if (resolved) {
		return 1;
	}

	dprint("Trying to load embedded python library\n");
	hmod = memdlopen(dllname, bytes, size);
	if (hmod == NULL) {
		dprint("Couldn't load embedded python library: %s\n", dlerror());
		return 0;
	}

	p = imports;
	for (i = 0; p->name; ++i, ++p) {
		p->proc = (void (*)()) dlsym(hmod, p->name);
		dprint("Python: %s -> %p\n", p->name, p->proc);
		if (p->proc == NULL) {
			dprint("undefined symbol %s -> exit(-1)\n", p->name);
			return 0;
		}
	}

	return 1;
}
