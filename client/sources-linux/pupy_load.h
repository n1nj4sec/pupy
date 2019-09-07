#ifndef PUPY_LOAD_H
#define PUPY_LOAD_H

#include <stdint.h>
#include <stdbool.h>

void initialize(bool isDll);
int execute(void * lpArg);
void deinitialize();

void setup_jvm_class();

#endif
