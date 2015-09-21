#ifndef _METERPRETER_REMOTE_THREAD_H
#define _METERPRETER_REMOTE_THREAD_H

HANDLE create_remote_thread(HANDLE hProcess, SIZE_T sStackSize, LPVOID pvStartAddress, LPVOID pvStartParam, DWORD dwCreateFlags, LPDWORD pdwThreadId);

#endif
