# A script to generate helper files for dynamic linking to the Python dll
#
import string
decls = '''
void, Py_InitializeEx, (int)
void, Py_Finalize, (void)
char *, Py_GetPath, (void)
void, Py_SetPythonHome, (const char *)
void, Py_SetProgramName, (const char *)
PyObject *, PyMarshal_ReadObjectFromString, (char *, Py_ssize_t)
int, PyString_AsStringAndSize, (PyObject *, char **, Py_ssize_t *)
const char *, PyString_AsString, (PyObject *)
int, PyArg_ParseTuple, (PyObject *, const char *, ...)
int, PyArg_ParseTupleAndKeywords, (PyObject *args, PyObject *kw, const char *format, const char * const *keywords, ...)
PyObject *, PyErr_Format, (PyObject *, const char *, ...)
PyObject *, PyImport_ImportModule, (const char *)
PyObject *, PyInt_FromLong, (long)
long, PyInt_AsLong, (PyObject *)
PyObject *, PyLong_FromVoidPtr, (void *)
PyObject *, Py_InitModule4, (const char *, PyMethodDef *, const char *, PyObject *, int)
int, Py_IsInitialized, (void)
int, PyObject_SetAttrString, (PyObject *, const char *, PyObject *)
PyObject *, PyCFunction_NewEx, (PyMethodDef *, PyObject *, PyObject *)
PyObject *, PyObject_GetAttrString, (PyObject *, const char *)
PyObject *, Py_BuildValue, (const char *, ...)
PyObject *, PyObject_Call, (PyObject *, PyObject *, PyObject *)
PyObject *, PyObject_CallFunctionObjArgs, (PyObject *, ...)
PyObject *, PyObject_CallFunction, (PyObject *, const char *, ...)
PyObject *, PyErr_Occurred, (void)
void, PyErr_Fetch, (PyObject **, PyObject **, PyObject **)
void, PyErr_Clear, (void)
int, PyObject_IsInstance, (PyObject *, PyObject *)
PyObject *, PyCapsule_New, (void *, const char *, void *)
void *, PyCapsule_GetPointer, (PyObject *, const char *)

void, Py_IncRef, (PyObject *)
void, Py_DecRef, (PyObject *)

PyObject, PyInt_Type
PyObject, _Py_NoneStruct
PyObject, _Py_ZeroStruct

PyObject *, PyErr_SetFromErrno, (PyObject *)
PyObject *, PyExc_ImportError
PyObject *, PyExc_Exception
PyObject *, PyExc_KeyError
PyObject *, PyExc_OSError
char *, _Py_PackageContext

int, Py_NoSiteFlag
int, Py_OptimizeFlag
int, Py_NoUserSiteDirectory
int, Py_DontWriteBytecodeFlag
int, Py_IgnoreEnvironmentFlag

PyObject *, PyObject_CallObject, (PyObject *, PyObject *)

PyGILState_STATE, PyGILState_Ensure, (void)
void, PyGILState_Release, (PyGILState_STATE)

void, PySys_SetObject, (const char *, PyObject *)
PyObject *, PyString_FromString, (const char *)
PyObject *, PyImport_AddModule, (const char *)
PyObject *, PyModule_GetDict, (PyObject *)
Py_ssize_t, PySequence_Length, (PyObject *)
PyObject *, PySequence_GetItem, (PyObject *, Py_ssize_t)
PyObject *, PyEval_EvalCode, (PyCodeObject *, PyObject *, PyObject *)
PyObject *, PyEval_GetBuiltins, ()
void, PyErr_Print, (void)
PyObject *, PyBool_FromLong, (long)
const char *, Py_FileSystemDefaultEncoding
PyObject*, PyList_New, (Py_ssize_t)
PyObject*, PyList_GetItem, (PyObject *, Py_ssize_t)
PyObject*, PyList_Append, (PyObject *, PyObject *)
int, PyObject_IsTrue, (PyObject *)
void, PyErr_SetString, (PyObject *, const char *)
void, PyEval_InitThreads, (void)

PyObject *, PyFile_FromFile, (FILE *fp, char *name, char *mode, int (*close)(FILE*))
void, PyFile_SetBufSize, (PyObject *, int)
PyObject *, PyErr_NewException, (const char *name, PyObject *base, PyObject *dict)
int, PyModule_AddObject, (PyObject *, const char *, PyObject *)
int, PyModule_AddStringConstant, (PyObject *module, const char *name, const char *value)

PyObject*, PyDict_New, ()
PyObject*, PyString_FromStringAndSize, (const char *v, Py_ssize_t len)
int, PyDict_Update, (PyObject *a, PyObject *b)
int, PyDict_SetItem, (PyObject *p, PyObject *key, PyObject *val)
int, PyDict_SetItemString, (PyObject *, const char *, PyObject *)
int, PyDict_DelItem, (PyObject *a, PyObject *b)
PyObject*, PyDict_GetItemString, (PyObject *p, const char *key)
'''.strip().splitlines()


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
        print >> hfile, '#define %(name)s ((%(restype)s(*)%(argtypes)s)py_sym_table[%(index)d].proc)' % locals(
        )
    elif len(items) == 2:
        # exported data
        typ, name = map(string.strip, items)
        print >> hfile, '#define %(name)s (*(%(typ)s(*))py_sym_table[%(index)s].proc)' % locals(
        )
    else:
        raise ValueError, "could not parse %r" % decl
    if name == "Py_InitModule4":
        print >> cfile, '#ifdef _DEBUG'
        print >> cfile, '\t{ "Py_InitModule4TraceRefs", NULL },' % locals()
        print >> cfile, '#else'
        print >> cfile, '#  if defined (__x86_64__) || defined (_WIN64)'
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
