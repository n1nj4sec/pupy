#ifndef PYTHON_DYNLOAD_OS_H
#define PYTHON_DYNLOAD_OS_H

#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef PYTHON_LIB_NAME
#define PYTHON_LIB_NAME "python310.so"
#endif

#include "Python-dynload.h"

#define FREE_HMODULE_AFTER_LOAD 1
#define FILE_SYSTEM_ENCODING "utf-8"

typedef void *HMODULE;
typedef void *(*resolve_symbol_t)(HMODULE hModule, const char *name);

#ifndef OPENSSL_LIB_VERSION
#define OPENSSL_LIB_VERSION "1.1"
#endif

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


#define DEPENDENCIES                          \
{                                             \
    {                                         \
        "libcrypto.so." OPENSSL_LIB_VERSION,  \
        libcrypto_c_start,                    \
        libcrypto_c_size,                     \
        FALSE                                 \
    }, {                                      \
        "libssl.so." OPENSSL_LIB_VERSION,     \
        libssl_c_start,                       \
        libssl_c_size,                        \
        FALSE                                 \
    }, {                                      \
        "libffi.so.6",                        \
        libffi_c_start,                       \
        libffi_c_size,                        \
        FALSE                                 \
    }, {                                      \
        "python310.so",                       \
        python3x_c_start,                     \
        python3x_c_size,                      \
        TRUE                                  \
    }                                         \
}

#define OSAlloc(size) malloc(size)
#define OSFree(ptr) free(ptr)

#define OSLoadLibrary(name) dlopen(name, RTLD_NOW)
#define OSResolveSymbol dlsym
#define OSUnmapRegion munmap
#define MemLoadLibrary(name, bytes, size, arg) \
    memdlopen(name, bytes, size, RTLD_NOW | RTLD_GLOBAL)
#define MemResolveSymbol dlsym
#define CheckLibraryLoaded(name) dlopen(name, RTLD_NOW | RTLD_NOLOAD)

#ifndef PYTHON_DYNLOAD_OS_NO_BLOBS
static const char *OSGetProgramName()
{
    static BOOL is_set = FALSE;
    static char exe[PATH_MAX] = {'\0'};

    if (is_set)
        return exe;

#if defined(Linux)
    dprint("INVOCATION NAME: %s\n", program_invocation_name);

    if (readlink("/proc/self/exe", exe, sizeof(exe)) > 0)
    {
        if (strstr(exe, "/memfd:"))
        {
            snprintf(exe, sizeof(exe), "/proc/%d/exe", getpid());
        }
    }
    else
    {
        char *upx_env = getenv("   ");
        if (upx_env)
        {
            snprintf(exe, sizeof(exe), "%s", upx_env);
        }
    }

#elif defined(SunOS)
    strcpy(exe, getexecname());
#endif

    is_set = TRUE;
    return exe;
}

#include "python3x.c"
#include "libcrypto.c"
#include "libssl.c"
#include "libffi.c"
#include "tmplibrary.h"
#endif

#endif
