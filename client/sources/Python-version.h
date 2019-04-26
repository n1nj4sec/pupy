# define PYTHON_API_VERSION 1013
# if defined (_WIN64)
     typedef __int64 Py_ssize_t;
# elif defined (_WIN32)
    typedef int Py_ssize_t;
# endif
