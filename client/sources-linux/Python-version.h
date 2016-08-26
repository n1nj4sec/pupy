#include <patchlevel.h>
#include <limits.h>
#include <stdint.h>

#if (PY_VERSION_HEX < 0x02050000)
#  define PYTHON_API_VERSION 1012
   typedef int Py_ssize_t;
#else
#  define PYTHON_API_VERSION 1013
#  if defined (__x86_64__)
     typedef intptr_t Py_ssize_t;
#  else
     typedef intptr_t Py_ssize_t;
#  endif
#endif
