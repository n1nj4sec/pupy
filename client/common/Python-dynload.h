/*
    WARNING !
    DEPENDS ON PYTHON ABI!
*/

#ifndef PYTHON_DYNLOAD_H
#define PYTHON_DYNLOAD_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define CO_MAXBLOCKS 20

typedef void *PyObject;

typedef struct {
    int b_type;
    int b_handler;
    int b_level;
} PyTryBlock;

typedef PyObject *(*PyCFunction)(PyObject *, PyObject *);

typedef
    enum {PyGILState_LOCKED, PyGILState_UNLOCKED}
        PyGILState_STATE;
typedef struct {
    char *ml_name;
    PyCFunction ml_meth;
    int ml_flags;
    char *ml_doc;
} PyMethodDef;

struct py_imports {
    char *name;
    void (*proc)();
};

#if defined(_MSC_VER) && _MSC_VER < 1600
#ifdef _WIN64
    #define ssize_t signed long long
#else
    #define ssize_t signed long
#endif
#endif

#ifndef Py_ssize_t
    #define Py_ssize_t ssize_t
#endif

#ifndef BOOL
    typedef int BOOL;
    #define TRUE 1
    #define FALSE 0
#endif

#ifndef Py_INCREF
    #define Py_INCREF Py_IncRef
#endif

#ifndef Py_DECREF
    #define Py_DECREF Py_DecRef
#endif

#ifndef Py_XINCREF
    #define Py_XINCREF(op) do { if ((op) == NULL) ; else Py_INCREF(op); } while (0)
#endif

#ifndef Py_XDECREF
    #define Py_XDECREF(op) do { if ((op) == NULL) ; else Py_DECREF(op); } while (0)
#endif

#ifdef _WIN32
    #define snprintf _snprintf
#endif

#define METH_OLDARGS  0x0000
#define METH_VARARGS  0x0001
#define METH_KEYWORDS 0x0002
/* METH_NOARGS and METH_O must not be combined with the flags above. */
#define METH_NOARGS   0x0004
#define METH_O        0x0008

/* METH_CLASS and METH_STATIC are a little different; these control
   the construction of methods for a class.  These cannot be used for
   functions in modules. */
#define METH_CLASS    0x0010
#define METH_STATIC   0x0020

#define PyCFunction_New(ML, SELF) PyCFunction_NewEx((ML), (SELF), NULL)

#define PyInt_Check(op) PyObject_IsInstance(op, &PyInt_Type) /* ??? */
#define Py_None (&_Py_NoneStruct)

#define DL_EXPORT(x) x

#define PYTHON_API_VERSION 1013

#define Py_InitModule3(name, methods, doc) \
       Py_InitModule4(name, methods, doc, (PyObject *)NULL, \
                      PYTHON_API_VERSION)

int Py_RefCnt(const PyObject *object);

extern struct py_imports py_sym_table[];

BOOL initialize_python(int argc, char *argv[], BOOL is_shared_object);
void run_pupy(void);
void deinitialize_python(void);

#define VPATH_PREFIX "pupy://"
#define VPATH_EXT ".pyo"

typedef struct {
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;

    int co_argcount;
    int co_nlocals;
    int co_stacksize;
    int co_flags;

    PyObject *co_code;
    PyObject *co_consts;
    PyObject *co_names;
    PyObject *co_varnames;
    PyObject *co_freevars;
    PyObject *co_cellvars;
    PyObject *co_filename;
    PyObject *co_name;
    int co_firstlineno;
    PyObject *co_lnotab;
    void *co_zombieframe;
    PyObject *co_weakreflist;
} PyCodeObject;

typedef struct _is {

    struct _is *next;
    struct _ts *tstate_head;

    PyObject *modules;
    PyObject *sysdict;
    PyObject *builtins;
    PyObject *modules_reloading;

    PyObject *codec_search_path;
    PyObject *codec_search_cache;
    PyObject *codec_error_registry;

    /* PRIVATE PART OMITTED */

} PyInterpreterState;

struct _frame;

typedef struct _ts {
    struct _ts *next;
    PyInterpreterState *interp;
    struct _frame *frame;

    int recursion_depth;
    int tracing;
    int use_tracing;

    void *c_profilefunc;
    void *c_tracefunc;

    PyObject *c_profileobj;
    PyObject *c_traceobj;

    PyObject *curexc_type;
    PyObject *curexc_value;
    PyObject *curexc_traceback;

    PyObject *exc_type;
    PyObject *exc_value;
    PyObject *exc_traceback;

    PyObject *dict;

    int tick_counter;
    int gilstate_counter;

    PyObject *async_exc;
    long thread_id;

    int trash_delete_nesting;
    PyObject *trash_delete_later;
} PyThreadState;

typedef struct _frame {
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;
    Py_ssize_t ob_size;

    struct _frame *f_back;
    PyCodeObject *f_code;
    PyObject *f_builtins;
    PyObject *f_globals;
    PyObject *f_locals;
    PyObject **f_valuestack;
    PyObject **f_stacktop;
    PyObject *f_trace;

    PyObject *f_exc_type, *f_exc_value, *f_exc_traceback;

    PyThreadState *f_tstate;
    int f_lasti;
    int f_lineno;
    int f_iblock;

    /* PRIVATE */
} PyFrameObject;

#include "import-tab.h"

#endif // PYTHON_DYNLOAD_H
