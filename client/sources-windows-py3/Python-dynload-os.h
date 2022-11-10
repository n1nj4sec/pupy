#ifndef PYTHON_DYNLOAD_OS_H
#define PYTHON_DYNLOAD_OS_H

#include <windows.h>

#define PYTHON_LIB_NAME "python310.dll"

#include "MyLoadLibrary.h"
#include "MemoryModule.h"
#include "resource_python_manifest.c"
#include "actctx.h"

#define FILE_SYSTEM_ENCODING "mbcs"

#ifndef PATH_MAX
#define PATH_MAX 260
#endif

typedef FARPROC (WINAPI *resolve_symbol_t) (HMODULE hModule, const char *name);

#define OSAlloc(size) LocalAlloc(LMEM_FIXED, size)
#define OSFree(ptr) LocalFree(ptr)

static HMODULE OSLoadLibrary(const char *dllname) {
    HMODULE hModule = NULL;
    hModule = GetModuleHandle(dllname);
    if (!hModule)
        hModule = LoadLibrary(dllname);

    return hModule;
}

#define OSResolveSymbol MyGetProcAddress

static HMODULE MemLoadLibrary(const char *dllname, char *bytes, size_t size, void *arg) {
    ULONG_PTR cookie = _My_ActivateActCtx();
    HMODULE hModule = MyLoadLibrary(dllname, bytes, arg);
    _My_DeactivateActCtx(cookie);
    return hModule;
}


typedef struct PyPreConfig {
    int _config_init; 
    int parse_argv;
    int isolated;
    int use_environment;
    int configure_locale;
    int coerce_c_locale;
    int coerce_c_locale_warn;
    int legacy_windows_fs_encoding;
    int utf8_mode;
    int dev_mode;
    int allocator;
} PyPreConfig;

typedef struct {
    enum {
        _PyStatus_TYPE_OK=0,
        _PyStatus_TYPE_ERROR=1,
        _PyStatus_TYPE_EXIT=2
    } _type;
    const char *func;
    const char *err_msg;
    int exitcode;
} PyStatus;

typedef struct {
    /* If length is greater than zero, items must be non-NULL
       and all items strings must be non-NULL */
    Py_ssize_t length;
    wchar_t **items;
} PyWideStringList;

typedef struct PyConfig {
    int _config_init;     /* _PyConfigInitEnum value */

    int isolated;
    int use_environment;
    int dev_mode;
    int install_signal_handlers;
    int use_hash_seed;
    unsigned long hash_seed;
    int faulthandler;
    int tracemalloc;
    int perf_profiling;
    int import_time;
    int code_debug_ranges;
    int show_ref_count;
    int dump_refs;
    wchar_t *dump_refs_file;
    int malloc_stats;
    wchar_t *filesystem_encoding;
    wchar_t *filesystem_errors;
    wchar_t *pycache_prefix;
    int parse_argv;
    PyWideStringList orig_argv;
    PyWideStringList argv;
    PyWideStringList xoptions;
    PyWideStringList warnoptions;
    int site_import;
    int bytes_warning;
    int warn_default_encoding;
    int inspect;
    int interactive;
    int optimization_level;
    int parser_debug;
    int write_bytecode;
    int verbose;
    int quiet;
    int user_site_directory;
    int configure_c_stdio;
    int buffered_stdio;
    wchar_t *stdio_encoding;
    wchar_t *stdio_errors;
#ifdef _WIN32
    int legacy_windows_stdio;
#endif
    wchar_t *check_hash_pycs_mode;
    int use_frozen_modules;
    int safe_path;
    int int_max_str_digits;

    /* --- Path configuration inputs ------------ */
    int pathconfig_warnings;
    wchar_t *program_name;
    wchar_t *pythonpath_env;
    wchar_t *home;
    wchar_t *platlibdir;

    /* --- Path configuration outputs ----------- */
    int module_search_paths_set;
    PyWideStringList module_search_paths;
    wchar_t *stdlib_dir;
    wchar_t *executable;
    wchar_t *base_executable;
    wchar_t *prefix;
    wchar_t *base_prefix;
    wchar_t *exec_prefix;
    wchar_t *base_exec_prefix;

    /* --- Parameter only used by Py_Main() ---------- */
    int skip_source_first_line;
    wchar_t *run_command;
    wchar_t *run_module;
    wchar_t *run_filename;

    /* --- Private fields ---------------------------- */

    // Install importlib? If equals to 0, importlib is not initialized at all.
    // Needed by freeze_importlib.
    int _install_importlib;

    // If equal to 0, stop Python initialization before the "main" phase.
    int _init_main;

    // If non-zero, disallow threads, subprocesses, and fork.
    // Default: 0.
    int _isolated_interpreter;

    // If non-zero, we believe we're running from a source tree.
    int _is_python_build;
} PyConfig;

#define MemResolveSymbol MyGetProcAddress
#define CheckLibraryLoaded MyGetModuleHandleA

#define OSUnmapRegion(start, size) do {} while(0)
       

        
#define DEPENDENCIES { \
        { \
            "VCRUNTIME140.DLL", \
            vcruntime140_c_start, vcruntime140_c_size, FALSE \
        }, \
        { \
            LIBCRYPTO, \
            libcrypto_c_start, libcrypto_c_size, FALSE \
        }, \
        { \
            LIBSSL, \
            libssl_c_start, libssl_c_size, FALSE \
        }, \
        { \
            LIBFFI, \
            libffi_c_start, libffi_c_size, FALSE \
        }, \
        { \
            "PYTHON310.DLL", \
            python3_c_start, python3_c_size, TRUE \
        } \
    }

#ifndef PYTHON_DYNLOAD_OS_NO_BLOBS
static char *OSGetProgramName() {
    static const char *program_name = "";
    static BOOL is_set = FALSE;

    wchar_t exe[PATH_MAX];
    int retval;

    if (is_set)
        return program_name;

    if (!GetModuleFileNameW(NULL, exe, PATH_MAX))
        return NULL;

    retval = WideCharToMultiByte(
        CP_UTF8, 0, exe, -1, NULL,
        0, NULL, NULL
    );

    if (!SUCCEEDED(retval))
        return NULL;

    program_name = LocalAlloc(LMEM_FIXED, retval);
    if (!program_name)
        return NULL;

    retval = WideCharToMultiByte(
        CP_UTF8, 0, exe, -1, program_name,
        retval, NULL, NULL
    );

    if (!SUCCEEDED(retval)) {
        LocalFree(program_name);
        return NULL;
    }

    is_set = TRUE;
    return program_name;
}

#include "vcruntime140.c"
#include "python3.c"
#include "libcrypto.c"
#include "libssl.c"
#include "libffi.c"
#endif

#endif // PYTHON_DYNLOAD_OS_H
