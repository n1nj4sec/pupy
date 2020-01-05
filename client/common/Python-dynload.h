#ifndef PYTHON_DYNLOAD_H
#define PYTHON_DYNLOAD_H

#include <stdint.h>
#include <sys/types.h>

typedef void *PyObject;
typedef void *PyCodeObject;

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
    #define ssize_t signed long long
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

#include "import-tab.h"

#endif // PYTHON_DYNLOAD_H
