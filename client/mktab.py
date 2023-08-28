from __future__ import print_function
from __future__ import unicode_literals

# A script to generate helper files for dynamic linking to the Python dll
#

import string
import sys

from io import open

UCS_ABI = 'UCS2'
if len(sys.argv) > 1:
    UCS_ABI = sys.argv[1]



decls = '''
void, Py_InitializeEx, (int)
void, Py_Finalize, ()
void, Py_Initialize, ()
wchar_t *, Py_GetPath, (void)
void, Py_SetPythonHome, (const wchar_t *)
void, Py_SetProgramName, (const wchar_t *)
PyObject *, PyMarshal_ReadObjectFromString, (char *, Py_ssize_t)
int, PyBytes_AsStringAndSize, (PyObject *, char **, Py_ssize_t *)
const char *, PyBytes_AsString, (PyObject *)
int, PyArg_ParseTuple, (PyObject *, const char *, ...)
int, PyArg_ParseTupleAndKeywords, (PyObject *args, PyObject *kw, const char *format, const char * const *keywords, ...)
PyObject *, PyImport_ImportModule, (const char *)
PyObject *, PyImport_Import, (PyObject *name)
PyObject *,PyLong_FromLong, (long)
PyObject *, PyLong_FromVoidPtr, (void *)
int, PyImport_ImportFrozenModule, (const char *name)
int, Py_IsInitialized, (void)
int, PyObject_SetAttrString, (PyObject *, const char *, PyObject *)
void*, PyUnicode_AsWideChar, (PyObject *o, wchar_t *w, Py_ssize_t size)
void, Py_SetPath, (const wchar_t* path)
Py_ssize_t, PyUnicode_GetSize, (PyObject *unicode)
const char *, PyUnicode_AsUTF8AndSize, (PyObject *unicode, Py_ssize_t *size)
const char *, PyUnicode_AsUTF8, (PyObject *unicode)
PyObject *, PyCFunction_NewEx, (PyMethodDef *, PyObject *, PyObject *)
PyObject *, PyObject_GetAttrString, (PyObject *, const char *)
PyObject *, Py_BuildValue, (const char *, ...)
PyObject *, PyObject_Call, (PyObject *, PyObject *, PyObject *)
PyObject *, PyObject_CallFunctionObjArgs, (PyObject *, ...)
PyObject *, PyObject_CallFunction, (PyObject *, const char *, ...)
PyObject *, PyErr_Occurred, (void)
void, PyErr_Fetch, (PyObject **, PyObject **, PyObject **)
void, PyErr_Clear, (void)
PyObject*, PyErr_NoMemory, (void)
int, PyObject_IsInstance, (PyObject *, PyObject *)
PyObject *, PyCapsule_New, (void *, const char *, void *)
void *, PyCapsule_GetPointer, (PyObject *, const char *)

void, Py_IncRef, (PyObject *)
void, Py_DecRef, (PyObject *)


PyObject*, PyErr_SetFromErrno, (PyObject *)
PyObject*, PyErr_Format, (PyObject *, const char *format, ...)



PyObject *, PyObject_CallObject, (PyObject *, PyObject *)

PyGILState_STATE, PyGILState_Ensure, (void)
void, PyGILState_Release, (PyGILState_STATE)

void, PySys_SetObject, (const char *, PyObject *)
PyObject *, PySys_GetObject, (const char *)
PyObject *, PyImport_AddModule, (const char *)
PyObject *, PyModule_GetDict, (PyObject *)
int, PyDict_Next, (PyObject *, Py_ssize_t *, PyObject **, PyObject **)
PyObject*, PyDict_Keys, (PyObject *)
void, PyDict_Clear, (PyObject *)
Py_ssize_t, PySequence_Length, (PyObject *)
PyObject *, PySequence_GetItem, (PyObject *, Py_ssize_t)
PyObject *, PyEval_EvalCode, (PyCodeObject *, PyObject *, PyObject *)
PyObject *, PyEval_GetBuiltins, ()
void, PyErr_Print, (void)
PyObject *, PyBool_FromLong, (long)
PyObject*, PyList_New, (Py_ssize_t)
PyObject*, PyList_GetItem, (PyObject *, Py_ssize_t)
PyObject*, PyList_Append, (PyObject *, PyObject *)
int, PyList_SetSlice, (PyObject *list, Py_ssize_t low, Py_ssize_t high, PyObject *itemlist)
Py_ssize_t, PyList_Size, (PyObject *list)
int, PyObject_IsTrue, (PyObject *)
PyObject*, PyObject_GetIter, (PyObject *)
PyObject*, PyIter_Next, (PyObject *o)
void, PyErr_SetString, (PyObject *, const char *)
void, PyEval_InitThreads, (void)

PyObject *, PyErr_NewException, (const char *name, PyObject *base, PyObject *dict)
int, PyModule_AddObject, (PyObject *, const char *, PyObject *)
int, PyModule_AddStringConstant, (PyObject *module, const char *name, const char *value)

PyObject*, PyDict_New, ()
PyObject*, PyUnicode_FromStringAndSize, (const char *v, Py_ssize_t len)
PyObject*, PyUnicode_FromString, (const char *u)
PyObject*, PyBytes_FromStringAndSize, (const char *v, Py_ssize_t len)
PyObject*, PyBytes_FromString, (const char *v)
int, PyDict_Update, (PyObject *a, PyObject *b)
int, PyDict_SetItem, (PyObject *p, PyObject *key, PyObject *val)
int, PyDict_SetItemString, (PyObject *, const char *, PyObject *)
int, PyDict_DelItem, (PyObject *a, PyObject *b)
PyObject*, PyDict_GetItemString, (PyObject *p, const char *key)
int, PyDict_DelItemString, (PyObject *p, const char *key)
wchar_t *, Py_DecodeLocale, (const char *arg, size_t *size)

PyStatus, _PyRuntime_Initialize, (void)

void, PyPreConfig_InitPythonConfig, (PyPreConfig *config)
void, PyPreConfig_InitIsolatedConfig, (PyPreConfig *config)
PyStatus, Py_PreInitialize, (PyPreConfig *config)

void, PyConfig_InitPythonConfig, (PyConfig *config)
void, PyConfig_InitIsolatedConfig, (PyConfig *config)
PyStatus, Py_InitializeFromConfig, (const PyConfig *config)
PyStatus, _Py_InitializeMain, (void)

int, PyStatus_Exception, (PyStatus status)
void, Py_ExitStatusException, (PyStatus status)

int , Py_NoSiteFlag
int , Py_OptimizeFlag
int , Py_NoUserSiteDirectory
int , Py_DontWriteBytecodeFlag
int , Py_IgnoreEnvironmentFlag
int , Py_IsolatedFlag
int , Py_UnbufferedStdioFlag

PyObject, PyUnicode_Type
PyObject, _Py_NoneStruct
const char *, _Py_PackageContext

char *, Py_FileSystemDefaultEncoding
PyObject *, PyExc_ImportError
PyObject *, PyExc_Exception
PyObject *, PyExc_KeyError
PyObject *, PyExc_OSError



int, PyImport_AppendInittab, (const char *name, PyObject *(*initfunc)(void))
int, PyRun_SimpleString, (const char *command)

int, _PyImport_FixupExtensionObject, (PyObject *mod, PyObject *name, PyObject *filename, PyObject *modules)
PyObject *, PyImport_GetModuleDict, ()

PyObject *, PyFile_FromFd, (int fd, const char *name, const char *mode, int buffering, const char *encoding, const char *errors, const char *newline, int closefd)

'''.strip().splitlines()

#int , Py_LegacyWindowsFSEncodingFlag

# useful types ?
"""
"""


hfile = open("import-tab.h", "w")
cfile = open("import-tab.c", "w")

index = 0
for decl in decls:
    if not decl or decl.startswith("//"):
        continue
    items = decl.split(',', 2)
    if len(items) == 3:
        # exported function with argument list
        restype, name, argtypes = map(str.strip, items)
        print(f'#define {name} (({restype}(*){argtypes})py_sym_table[{index}].proc)', file=hfile)
    elif len(items) == 2:
        # exported data
        typ, name = map(str.strip, items)
        print(f'#define {name} (*(({typ}(*))py_sym_table[{index}].proc))', file=hfile)
    else:
        raise ValueError("could not parse %r" % decl)
    print(f'\t{{ "{name}", NULL }},', file=cfile)
    index += 1

hfile.close()
cfile.close()
