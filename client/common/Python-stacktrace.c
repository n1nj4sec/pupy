#include "debug.h"
#include "Python-dynload-os.h"
#include "Python-dynload.h"

typedef void (*Py_GetStackTraceCb_t) (const char *line, void *cbdata);
typedef int (*Py_IsInitialized_t)(void);
typedef int (*PyEval_ThreadsInitialized_t)(void);
typedef PyGILState_STATE (*PyGILState_Ensure_t)(void);
typedef void (*PyGILState_Release_t)(PyGILState_STATE);
typedef PyThreadState* (*PyGILState_GetThisThreadState_t)(void);
typedef int (*PyCode_Addr2Line_t)(PyCodeObject *, int);

static
int Py_GetCurrentThreadStackTrace(Py_GetStackTraceCb_t cb, void *cbdata) {
    Py_IsInitialized_t pIsInitialized = NULL;
    PyEval_ThreadsInitialized_t pThreadsInitialized = NULL;
    PyGILState_Ensure_t pGILState_Ensure = NULL;
    PyGILState_Release_t pGILState_Release = NULL;
    PyGILState_GetThisThreadState_t pGILState_GetThisThreadState = NULL;
    PyCode_Addr2Line_t pCode_Addr2Line = NULL;

    PyGILState_STATE GIL_state;
    PyThreadState* Current_Thread_state;
    PyThreadState* Thread_state;
    BOOL blCurrentThreadDumped = FALSE;
    DWORD dwDumpedThreadsCount = 0;

    HMODULE hPythonLib = CheckLibraryLoaded(PYTHON_LIB_NAME);
    if (!hPythonLib) {
        dprint(
            "Py_GetCurrentThreadStackTrace: python lib (\"%s\") not found\n",
            PYTHON_LIB_NAME
        );
        return -1;
    }

    pIsInitialized = (Py_IsInitialized_t) MemResolveSymbol(
      hPythonLib, "Py_IsInitialized");
    pThreadsInitialized = (PyEval_ThreadsInitialized_t) MemResolveSymbol(
      hPythonLib, "PyEval_ThreadsInitialized");
    pGILState_Ensure = (PyGILState_Ensure_t) MemResolveSymbol(
      hPythonLib, "PyGILState_Ensure");
    pGILState_Release = (PyGILState_Release_t) MemResolveSymbol(
      hPythonLib, "PyGILState_Release");
    pGILState_GetThisThreadState = (PyGILState_GetThisThreadState_t) MemResolveSymbol(
      hPythonLib, "PyGILState_GetThisThreadState");
    pCode_Addr2Line = (PyCode_Addr2Line_t) MemResolveSymbol(
      hPythonLib, "PyCode_Addr2Line");

    if (!(pIsInitialized && pThreadsInitialized && pGILState_Ensure &&
            pGILState_Release && pGILState_GetThisThreadState && pCode_Addr2Line))
    {
        dprint(
            "Py_GetCurrentThreadStackTrace: Not all functions found\n"
        );
        return -2;
    }

    if (!pIsInitialized()) {
        dprint(
            "Py_GetCurrentThreadStackTrace: Python is not initialized\n"
        );
        return -3;
    }

    if (!pThreadsInitialized()) {
        dprint(
            "Py_GetCurrentThreadStackTrace: Python threads are not initialized\n"
        );

        return -4;
    }

    Current_Thread_state = pGILState_GetThisThreadState();
    if (!Current_Thread_state) {
        dprint(
            "Py_GetCurrentThreadStackTrace: Thread state is NULL\n"
        );

        return -5;
    }

    dprint("Py_GetCurrentThreadStackTrace: start\n");
    GIL_state = pGILState_Ensure();

    Thread_state = Current_Thread_state;

    while (Thread_state && dwDumpedThreadsCount ++ < 256) {
        if (Thread_state == Current_Thread_state) {
            if (blCurrentThreadDumped) {
                dprint("Current thread was already dumped\n");
                Thread_state = Thread_state->next;
                continue;
            } else {
                dprint("Dumping current thread first time\n");
                cb(cbdata, "Current Thread", NULL, Thread_state->thread_id);
            }
        } else {
            cb(cbdata, "Thread", NULL, Thread_state->thread_id);
        }

        if (Thread_state->frame) {
            PyFrameObject *frame = Thread_state->frame;

            dprint(
                "Py_GetCurrentThreadStackTrace: parse %p (Thread ID: %d)\n",
                frame, Thread_state->thread_id
            );

            dprint(
                "Py_GetCurrentThreadStackTrace: Top frame object: %p size=%d refs=%d\n",
                frame, frame->ob_size, frame->ob_refcnt
            );

            dprint(
                "Py_GetCurrentThreadStackTrace: Top frame code object: %p refs=%d\n",
                frame->f_code, frame->f_code->ob_refcnt
            );

            dprint(
                "Py_GetCurrentThreadStackTrace: Top frame code object: function=%s, file=%s\n",
                frame->f_code->co_name, frame->f_code->co_filename
            );

            while (frame) {
                int line = pCode_Addr2Line(frame->f_code, frame->f_lasti);
                const char *funcname = PyString_AsString(frame->f_code->co_name);
                const char *filename = PyString_AsString(frame->f_code->co_filename);

                dprint(
                    "Py_GetCurrentThreadStackTrace: func=%s file=%s line=%d\n",
                    funcname, filename, line
                );

                cb(cbdata, funcname, filename, line);

                frame = frame->f_back;
            }
        }

        if (Thread_state == Current_Thread_state) {
            dprint("Switching to all threads\n");
            Thread_state = Current_Thread_state->interp->tstate_head;
            blCurrentThreadDumped = TRUE;
        } else {
            dprint("Continue to dump all threads\n");
            Thread_state = Thread_state->next;
        }
    }

    pGILState_Release(GIL_state);
    dprint("Py_GetCurrentThreadStackTrace: complete\n");
    return 0;
}
