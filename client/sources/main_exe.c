#include <windows.h>
#include <winbase.h>
#include <winuser.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pupy_load.h"
#include "debug.h"

void on_exit_session(void);

static BOOL on_exit_session_called = FALSE;

#ifdef HAVE_WINDOW
LRESULT CALLBACK WinProc (HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_QUERYENDSESSION:
    case WM_CLOSE:
    case WM_QUIT:
        if (on_exit_session && !on_exit_session_called) {
            on_exit_session_called = TRUE;
            on_exit_session();
        }
        return 1;

    default:
        return DefWindowProc (hwnd, msg, wParam, lParam);
    }

    return 0;
}

int PASCAL WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpszCmdLine, int nCmdShow)
{
    MSG msg;
    BOOL bRet;
    WNDCLASS wc;
    HWND hwndMain;
    HINSTANCE hinst;
    HANDLE hThread;
    DWORD threadId;
    DWORD dwWake;
    WNDCLASSEX wx;
    static const char class_name[] = "DUMMY";

#ifdef DEBUG
    AttachConsole(-1);
#endif

    ZeroMemory(&wx, sizeof(WNDCLASSEX));

    wx.cbSize = sizeof(WNDCLASSEX);
    wx.lpfnWndProc = WinProc;
    wx.hInstance = hInstance;
    wx.lpszClassName = class_name;

    if ( ! RegisterClassEx(&wx) ) {
		dprint("RegisterClassEx failed: %d\n", GetLastError());
        return -1;
	}

    hwndMain = CreateWindowEx(
         0,
         class_name,
         NULL,
         0, 0, 0, 0, 0,
         NULL, NULL, NULL, NULL
    );

    if (!hwndMain) {
		dprint("CreateWindowEx failed: %d\n", GetLastError());
		return -2;
	}

    hThread = CreateThread(
        NULL,
        0,
        mainThread,
        NULL,
        0,
        &threadId
    );

    if (!hThread) {
		dprint("CreateThread failed: %d\n", GetLastError());
        return -GetLastError();
    }

	for (;;) {
		dwWake = MsgWaitForMultipleObjects(
			1,
			&hThread,
			FALSE,
			INFINITE,
			QS_ALLINPUT
        );

		switch (dwWake) {
		case WAIT_FAILED:
			return -3;

		case WAIT_TIMEOUT:
			continue;

		case WAIT_OBJECT_0:
			return 0;

		case WAIT_OBJECT_0 + 1:
			while (PeekMessage( &msg, NULL, 0, 0, PM_REMOVE)) {
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
			break;
		}
    }

    // We should never get here
    return -1;
}
#else
int main()
{
    mainThread(NULL);
}
#endif
