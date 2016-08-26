# A script to generate helper files for dynamic linking to the Python dll
#
decls = '''
void, Py_Initialize, (void)
void, Py_InitializeEx, (int)
int, PyRun_SimpleString, (char *)
void, Py_Finalize, (void)
char *, Py_GetPath, (void)
void, PySys_SetPath, (char *)
void, Py_SetPythonHome, (char *)
void, Py_SetProgramName, (char *)
PyObject *, PyMarshal_ReadObjectFromString, (char *, Py_ssize_t)
PyObject *, PyObject_CallFunction, (PyObject *, char *, ...)
int, PyString_AsStringAndSize, (PyObject *, char **, Py_ssize_t *)
char *, PyString_AsString, (PyObject *)
int, PyArg_ParseTuple, (PyObject *, char *, ...)
PyObject *, PyErr_Format, (PyObject *, const char *, ...)
PyObject *, PyImport_ImportModule, (char *)
PyObject *, PyInt_FromLong, (long)
long, PyInt_AsLong, (PyObject *)
PyObject *, PyLong_FromVoidPtr, (void *)
PyObject *, Py_InitModule4, (char *, PyMethodDef *, char *, PyObject *, int)
PyObject *, PyTuple_New, (Py_ssize_t)
int, PyTuple_SetItem, (PyObject*, Py_ssize_t, PyObject *)
int, Py_IsInitialized, (void)
int, PyObject_SetAttrString, (PyObject *, char *, PyObject *)
PyObject *, PyCFunction_NewEx, (PyMethodDef *, PyObject *, PyObject *)
PyObject *, PyObject_GetAttrString, (PyObject *, char *)
PyObject *, Py_BuildValue, (char *, ...)
PyObject *, PyObject_Call, (PyObject *, PyObject *, PyObject *)
void, PySys_WriteStderr, (const char *, ...)
PyObject *, PyErr_Occurred, (void)
void, PyErr_Clear, (void)
int, PyObject_IsInstance, (PyObject *, PyObject *)

PyObject, PyInt_Type
PyObject, _Py_NoneStruct
PyObject, _Py_ZeroStruct

PyObject *, PyExc_ImportError
PyObject *, PyExc_Exception
char *, _Py_PackageContext

PyGILState_STATE, PyGILState_Ensure, (void)
void, PyGILState_Release, (PyGILState_STATE)

void, PySys_SetObject, (char *, PyObject *)
PyObject *, PySys_GetObject, (char *)
PyObject *, PyString_FromString, (char *)
int, Py_FdIsInteractive, (FILE *, char *)
int, PyRun_InteractiveLoop, (FILE *, char *)
void, PySys_SetArgv, (int, char **)
PyObject *, PyImport_AddModule, (char *)
PyObject *, PyModule_GetDict, (PyObject *)
Py_ssize_t, PySequence_Length, (PyObject *)
PyObject *, PySequence_GetItem, (PyObject *, Py_ssize_t)
//int, PyCode_Check, (PyObject *)
PyObject *, PyEval_EvalCode, (PyCodeObject *, PyObject *, PyObject *)
void, PyErr_Print, (void)
PyObject *, PyBool_FromLong, (long)
int, Py_VerboseFlag
int, Py_NoSiteFlag
int, Py_OptimizeFlag
int, Py_IgnoreEnvironmentFlag
PyObject *, PyObject_Str, (PyObject *)
PyObject *, PyList_New, (Py_ssize_t)
int, PyList_SetItem, (PyObject *, Py_ssize_t, PyObject *)
int, PyList_Append, (PyObject *, PyObject *)
PyObject *, PyThreadState_GetDict, (void)
int, PyObject_IsTrue, (PyObject *)
void, PyErr_SetString, (PyObject *, const char *)
void, PyEval_InitThreads, (void)
void, PySys_SetArgvEx, (int, char **, int)
'''.strip().splitlines()

import string

hfile = open("import-tab.h", "w")
cfile = open("import-tab.c", "w")

index = 0
for decl in decls:
    if not decl or decl.startswith("//"):
        continue
    items = decl.split(',', 2)
    if len(items) == 3:
        # exported function with argument list
        restype, name, argtypes = map(string.strip, items)
        print >> hfile, '#define %(name)s ((%(restype)s(*)%(argtypes)s)imports[%(index)d].proc)' % locals()
    elif len(items) == 2:
        # exported data
        typ, name = map(string.strip, items)
        print >> hfile, '#define %(name)s (*(%(typ)s(*))imports[%(index)s].proc)' % locals()
    else:
        raise ValueError, "could not parse %r" % decl
    if name == "Py_InitModule4":
        print >> cfile, '#ifdef _DEBUG'
        print >> cfile, '\t{ "Py_InitModule4TraceRefs", NULL },' % locals()
        print >> cfile, '#else'
        print >> cfile, '#  if defined (__x86_64__)'
        print >> cfile, '\t{ "Py_InitModule4_64", NULL },' % locals()
        print >> cfile, '#  else'
        print >> cfile, '\t{ "Py_InitModule4", NULL },' % locals()
        print >> cfile, '#  endif'
        print >> cfile, '#endif'
    else:
        print >> cfile, '\t{ "%(name)s", NULL },' % locals()

    index += 1

hfile.close()
cfile.close()
