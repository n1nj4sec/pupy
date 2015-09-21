/*
  For the _memimporter compiled into py2exe exe-stubs we need "Python-dynload.h".
  For the standalone .pyd we need <Python.h>
*/

#ifdef STANDALONE
#  include <Python.h>
#  include "Python-version.h"
#else
#  include "Python-dynload.h"
#  include <stdio.h>
#endif
#include <windows.h>

static char module_doc[] =
"Importer which can load extension modules from memory";

//#include "MemoryModule.h"
#include "MyLoadLibrary.h"
#include "actctx.h"


static PyObject *
import_module(PyObject *self, PyObject *args)
{
	char *data;
	int size;
	char *initfuncname;
	char *modname;
	char *pathname;
	//HMEMORYMODULE hmem;
	HMODULE hmem;
	FARPROC do_init;

	ULONG_PTR cookie = 0;
	char *oldcontext;

	/* code, initfuncname, fqmodulename, path */
	if (!PyArg_ParseTuple(args, "s#sss:import_module",
			      &data, &size,
			      &initfuncname, &modname, &pathname))
		return NULL;
	cookie = _My_ActivateActCtx();//try some windows manifest magic...
	hmem=MyLoadLibrary(pathname, data, NULL);
	_My_DeactivateActCtx(cookie);
	if (!hmem) {
		PyErr_Format(PyExc_ImportError,
			     "MemoryLoadLibrary failed loading %s", pathname);
		return NULL;
	}
	do_init = MyGetProcAddress(hmem, initfuncname);
	if (!do_init) {
		MyFreeLibrary(hmem);
		PyErr_Format(PyExc_ImportError,
			     "Could not find function %s", initfuncname);
		return NULL;
	}

    oldcontext = _Py_PackageContext;
	_Py_PackageContext = modname;
	do_init();
	_Py_PackageContext = oldcontext;
	if (PyErr_Occurred())
		return NULL;
	/* Retrieve from sys.modules */
	return PyImport_ImportModule(modname);
}

static PyObject *
get_verbose_flag(PyObject *self, PyObject *args)
{
	return PyInt_FromLong(Py_VerboseFlag);
}

static PyMethodDef methods[] = {
	{ "import_module", import_module, METH_VARARGS,
	  "import_module(data, size, initfuncname, path) -> module" },
	{ "get_verbose_flag", get_verbose_flag, METH_NOARGS,
	  "Return the Py_Verbose flag" },
	{ NULL, NULL },		/* Sentinel */
};

DL_EXPORT(void)
init_memimporter(void)
{
	Py_InitModule3("_memimporter", methods, module_doc);
}

