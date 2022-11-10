#ifndef PYTHONINTERPRETER
#define PYTHONINTERPRETER

#include <windows.h>

typedef VOID (*on_exit_session_t)(VOID);

#ifdef _PUPY_DYNLOAD

typedef struct _pupy_pyd_args {
    PVOID *pvMemoryLibraries;
    on_exit_session_t cbExit;
    BOOL blInitialized;
} _pupy_pyd_args_t;
#else
void on_exit_session(void);
#endif


void initialize(BOOL isDll);
DWORD WINAPI execute(LPVOID lpArg);
void deinitialize();

void setup_jvm_class();

#endif
