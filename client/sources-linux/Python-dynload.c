/* **************** Python-dynload.c **************** */
#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include "Python-dynload.h"
#include "tmplibrary.h"
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "debug.h"

struct IMPORT imports[] = {
#include "import-tab.c"
    { NULL, NULL }, /* sentinel */
};

typedef struct python_search {
    const char *libname;
    void *base;
} python_search_t;

int _load_python(void *hmod)
{
    int i;
    struct IMPORT *p = imports;

    p = imports;
    for (i = 0; p->name; ++i, ++p) {
        p->proc = (void (*)()) dlsym(hmod, p->name);
        dprint("Python: %s -> %p\n", p->name, p->proc);
        if (p->proc == NULL) {
            dprint("undefined symbol %s -> exit(-1)\n", p->name);
            return 0;
        }
    }

    return 1;
}
