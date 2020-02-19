#ifndef PYTHON_STACKTRACE_H
#define PYTHON_STACKTRACE_H

typedef void (*Py_GetStackTraceCb_t)(
    void *cbdata, const char *function, const char *file, unsigned int line
);

static  int Py_GetCurrentThreadStackTrace(Py_GetStackTraceCb_t cb, void *cbdata);

#endif

