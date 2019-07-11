#include "debug.h"

static FILE* debug_log = NULL;

int dprint(const char *fmt, ...) {
    va_list args;
    int n;
    FILE *log = stdout;

    if (debug_log != NULL)
        log = debug_log;

    va_start (args, fmt);
    n = vfprintf(log, fmt, args);
    va_end (args);
    fflush(log);
    return n;
}

void set_debug_log(const char *dest) {
    FILE * new_debug_log = fopen(dest, "w+");
    FILE * old_debug_log = debug_log;
    if (!new_debug_log) {
        dprint("Failed to open new debug log dest: %s\n", dest);
        return;
    }

    dprint("Redirecting debug log to %s\n", dest);

    debug_log = new_debug_log;

    if (old_debug_log)
        fclose(old_debug_log);
}
