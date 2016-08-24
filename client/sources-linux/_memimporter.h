#ifndef _MEMIMPORTER_H
#define _MEMIMPORTER_H

#include <stdbool.h>

bool
import_module(const char *initfuncname, char *modname, const char *data, size_t size);
void init_memimporter(void);

#endif
