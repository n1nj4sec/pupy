/* **************** Python-dynload.h **************** */
#include "Python-version.h"

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

struct IMPORT {
	char *name;
	void (*proc)();
};
extern int _load_python(char *dllname, char *dllbytes);
extern struct IMPORT imports[];

#include "import-tab.h"

extern void Py_XINCREF(PyObject *);
#define snprintf _snprintf
#define Py_DECREF(x) Py_XDECREF(x)
#define Py_INCREF(x) Py_XINCREF(x)

extern void Py_XDECREF(PyObject *ob);

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

#define Py_InitModule3(name, methods, doc) \
	Py_InitModule4(name, methods, doc, (PyObject *)NULL, \
		       PYTHON_API_VERSION)
