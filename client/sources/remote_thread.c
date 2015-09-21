//#include "common.h"
#include <windows.h>
#include "remote_thread.h"
/*! @brief Container structure for a client identifer used when creating remote threads with RtlCreateUserThread. */
typedef struct _MIMI_CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENTID;

/*! @brief Function pointer type for the RtlCreateUserThread function in ntdll.dll */
typedef NTSTATUS (WINAPI * PRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, SIZE_T, SIZE_T, PTHREAD_START_ROUTINE, PVOID, PHANDLE, CLIENTID*);
/*! @brief Reference to the loaded RtlCreateUserThread function pointer. */
static PRtlCreateUserThread pRtlCreateUserThread = NULL;
/*! @brief Indication of whether an attempt to locate the pRtlCreateUserThread pointer has been made. */
static BOOL pRtlCreateUserThreadAttempted = FALSE;

/*!
 * @brief Helper function for creating a remote thread in a privileged process.
 * @param hProcess Handle to the target process.
 * @param sStackSize Size of the stack to use (if unsure, specify 0).
 * @param pvStartAddress Pointer to the function entry point that has been loaded into the target.
 * @param pvStartParam Pointer to the parameter to pass to the thread function.
 * @param dwCreateFlags Creation flags to use when creating the new thread.
 * @param pdwThreadId Pointer to the buffer that will receive the thread ID (optional).
 * @return Handle to the new thread.
 * @retval NULL Indicates an error, which can be retrieved with \c GetLastError().
 * @remark This function has been put in place to wrap up the handling of creating remote threads
 *         in privileged processes across all operating systems. In Windows XP and earlier, the
 *         \c CreateRemoteThread() function was sufficient to handle this case, however this changed
 *         in Vista and has been that way since. For Vista onwards, the use of the hidden API function
 *         \c RtlCreateUserThread() is required. This function attempts to use \c CreateRemoteThread()
 *         first and if that fails it will fall back to \c RtlCreateUserThread(). This means that the
 *         existing behaviour is kept for when running on XP and earlier, or when the user is already
 *         running within a privileged process.
 */
HANDLE create_remote_thread(HANDLE hProcess, SIZE_T sStackSize, LPVOID pvStartAddress, LPVOID pvStartParam, DWORD dwCreateFlags, LPDWORD pdwThreadId)
{
	NTSTATUS ntResult;
	BOOL bCreateSuspended;
	DWORD dwThreadId;
	HANDLE hThread;
	
	if (pdwThreadId == NULL)
	{
		pdwThreadId = &dwThreadId;
	}

	hThread = CreateRemoteThread(hProcess, NULL, sStackSize, (LPTHREAD_START_ROUTINE)pvStartAddress, pvStartParam, dwCreateFlags, pdwThreadId);

	// ERROR_NOT_ENOUGH_MEMORY is returned when the function fails due to insufficient privs
	// on Vista and later.
	if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
	{
		//dprintf("[REMOTETHREAD] CreateRemoteThread seems to lack permissions, trying alternative options");
		hThread = NULL;

		// Only attempt to load the function pointer if we haven't attempted it already.
		if (!pRtlCreateUserThreadAttempted)
		{
			if (pRtlCreateUserThread == NULL)
			{
				pRtlCreateUserThread = (PRtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread");
				if (pRtlCreateUserThread)
				{
					//dprintf("[REMOTETHREAD] RtlCreateUserThread found at %p, using for backup remote thread creation", pRtlCreateUserThread);
				}
			}
			pRtlCreateUserThreadAttempted = TRUE;
		}

		// if at this point we don't have a valid pointer, it means that we don't have this function available
		// on the current OS
		if (pRtlCreateUserThread)
		{
			DWORD (WINAPI *fGetThreadId)(HANDLE Thread);
			fGetThreadId = (void*)GetProcAddress(GetModuleHandleA("kernel32"), "GetThreadId");
			if(fGetThreadId){
			//dprintf("[REMOTETHREAD] Attempting thread creation with RtlCreateUserThread");
			bCreateSuspended = (dwCreateFlags & CREATE_SUSPENDED) == CREATE_SUSPENDED;
			ntResult = pRtlCreateUserThread(hProcess, NULL, bCreateSuspended, 0, 0, 0, (PTHREAD_START_ROUTINE)pvStartAddress, pvStartParam, &hThread, NULL);
			SetLastError(ntResult);

			if (ntResult == 0 && pdwThreadId)
			{
				*pdwThreadId = fGetThreadId(hThread);
			}
			}
		}
		else
		{
			// restore the previous error so that it looks like we haven't done anything else
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		}
	}

	return hThread;
}


