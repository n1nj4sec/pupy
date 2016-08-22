/* **************** Python-dynload.c **************** */
#include <stdlib.h>
#include <sys/types.h>
#include "Python-dynload.h"
#include "tmplibrary.h"
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

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

int _load_python_FromFile(const char *dllname)
{
	int i;
	struct IMPORT *p = imports;
	void *hmod;

	// In some cases (eg, ISAPI filters), Python may already be
	// in our process.  If so, we don't want it to try and
	// load a new one!  (Actually, we probably should not even attempt
	// to load an 'embedded' Python should GetModuleHandle work - but
	// that is less clear than this straight-forward case)
	// Get the basename of the DLL.
	const char *dllbase = dllname + strlen(dllname);
	while (dllbase != dllname && (*dllbase != '\\' || *dllbase != '/'))
		dllbase--;
	if (*dllbase=='\\' || *dllbase=='/')
		++dllbase;
	hmod = dlopen(dllbase, RTLD_NOW);
	if (hmod == NULL)
		hmod = dlopen(dllname, RTLD_NOW);
	if (hmod == NULL) {
		return 0;
	}

	for (i = 0; p->name; ++i, ++p) {
		p->proc = (void (*)()) dlsym(hmod, p->name);
		if (p->proc == NULL) {
			fprintf(stderr, "undefined symbol %s -> exit(-1)\n", p->name);
			return 0;
		}
	}

	return 1;
}

int _load_python(const char *dllname, const char *bytes, size_t size)
{
	int i;
	struct IMPORT *p = imports;
	void * hmod;
	if (!bytes)
		return _load_python_FromFile(dllname);

	hmod = memdlopen(dllname, bytes, size);
	if (hmod == NULL) {
		return 0;
	}

	for (i = 0; p->name; ++i, ++p) {
		p->proc = (void (*)()) dlsym(hmod, p->name);
		if (p->proc == NULL) {
			fprintf(stderr, "undefined symbol %s -> exit(-1)\n", p->name);
			return 0;
		}
	}

	return 1;
}
