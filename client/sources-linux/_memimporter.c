#include <stdint.h>
#include <dlfcn.h>
#include "tmplibrary.h"

#ifdef STANDALONE
#  include <Python.h>
#  include "Python-version.h"
#  error "Shouldn't be here"
#else
#  include "Python-dynload.h"
#  include <stdio.h>
#endif

#include "_memimporter.h"
#include "debug.h"

static char module_doc[] =
"Importer which can load extension modules from memory";

bool
import_module(const char *initfuncname, char *modname, const char *data, size_t size) {
    char *oldcontext;

    dprint("import_module: init=%s mod=%s (%p:%lu)\n",
           initfuncname, modname, data, size);

    void *hmem=memdlopen(modname, data, size);
    if (!hmem) {
        dprint("Couldn't load %s: %m\n", modname);
        return false;
    }

    void (*do_init)() = dlsym(hmem, initfuncname);
    if (!do_init) {
        dprint("Couldn't find sym %s in %s: %m\n", initfuncname, modname);
        dlclose(hmem);
        return false;
    }

    oldcontext = _Py_PackageContext;
    _Py_PackageContext = modname;
    dprint("Call %s@%s\n", initfuncname, modname);
    do_init();
    _Py_PackageContext = oldcontext;

    dprint("Call %s@%s - complete\n", initfuncname, modname);

    return true;
}

static PyObject *
Py_import_module(PyObject *self, PyObject *args) {
    char *data;
    int size;
    char *initfuncname;
    char *modname;
    char *pathname;

    /* code, initfuncname, fqmodulename, path */
    if (!PyArg_ParseTuple(args, "s#sss:import_module",
                  &data, &size,
                  &initfuncname, &modname, &pathname)) {
        return NULL;
    }

    dprint("DEBUG! %s@%s\n", initfuncname, modname);

    if (!import_module(initfuncname, modname, data, size)) {
        PyErr_Format(PyExc_ImportError,
                 "Could not find function %s", initfuncname);
        return NULL;
    }

    /* Retrieve from sys.modules */
    return PyImport_ImportModule(modname);
}

static PyObject *
get_verbose_flag(PyObject *self, PyObject *args)
{
    return PyInt_FromLong(Py_VerboseFlag);
}

static PyMethodDef methods[] = {
    { "import_module", Py_import_module, METH_VARARGS,
      "import_module(data, size, initfuncname, path) -> module" },
    { "get_verbose_flag", get_verbose_flag, METH_NOARGS,
      "Return the Py_Verbose flag" },
    { NULL, NULL },     /* Sentinel */
};

DL_EXPORT(void)
init_memimporter(void)
{
    dprint("Importing... %p\n", Py_InitModule4);
    Py_InitModule3("_memimporter", methods, module_doc);
}
