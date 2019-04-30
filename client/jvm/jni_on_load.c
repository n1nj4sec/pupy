#include "jni.h"
#include "debug.h"

/* // TODO: Add proper deinitialization.. */

static JavaVM *__jvm = NULL;

static jobject __j_initial_classloader = NULL;
static jobject __j_preferred_classloader = NULL;
static jclass __j_ClassLoader = NULL;
static jmethodID __j_ClassLoader_findClass = NULL;

static PyObject * jvm_error = NULL;
static char *__preferred_classloader_name = NULL;
static char *__preferred_loadable_class = NULL;
static char jvm_module_doc[] = "Info about parent JVM";

struct __thread_name_and_classloader_to_dict_ctx {
        void* payload;

        jclass Thread;
        jclass Class;

        jstring prefferedName;

        jmethodID getName;
        jmethodID getContextClassLoader;
        jmethodID getClass;
        jmethodID forName;
        jmethodID getClassName;
};

static JNIEnv*
Py_get_jni_env(JNIEnv *env) {
        jint ret;
        void *penv = NULL;

        if (env != NULL)
                return env;

        if (__jvm == NULL) {
                PyErr_SetString(jvm_error, "JVM was not loaded yet");
                return NULL;
        }

        ret = (*__jvm)->GetEnv(__jvm, &penv,  JNI_VERSION_1_6);
        switch (ret) {
        case JNI_OK:
                dprint("Load JNIEnv: %p\n", penv);
                break;

        case JNI_EDETACHED:
                PyErr_SetString(jvm_error, "Method called from detached thread");
                return NULL;

        default:
                PyErr_SetString(jvm_error, "Could not get JNI Environment");
                return NULL;
        }

        return penv;
}


static jint Py_new__thread_name_and_classloader_to_dict_ctx(
        JNIEnv *env, struct __thread_name_and_classloader_to_dict_ctx *ctx) {

        ctx->Thread = (*env)->FindClass(env, "java/lang/Thread");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "java/lang/Thread class not found");
                return JNI_ERR;
        }

        dprint("ctx->Thread: %p\n", ctx->Thread);

        ctx->Class = (*env)->FindClass(env, "java/lang/Class");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "java/lang/Class class not found");
                return JNI_ERR;
        }

        dprint("ctx->Class: %p\n", ctx->Class);

        ctx->getName = (*env)->GetMethodID(env, ctx->Thread, "getName", "()Ljava/lang/String;");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "getName method not found");
                return JNI_ERR;
        }

        dprint("ctx->getName: %p\n", ctx->getName);

        ctx->getContextClassLoader = (*env)->GetMethodID(
                env, ctx->Thread, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "getContextClassLoader method not found");
                return JNI_ERR;
        }

        dprint("ctx->getContextClassLoader: %p\n", ctx->getContextClassLoader);

        ctx->forName = (*env)->GetStaticMethodID(
                env, ctx->Class, "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "forName method not found");
                return JNI_ERR;
        }

        dprint("ctx->getContextClassLoader: %p\n", ctx->forName);

        dprint("__j_ClassLoader %p\n", __j_ClassLoader);

        ctx->getClass = (*env)->GetMethodID(env, __j_ClassLoader, "getClass", "()Ljava/lang/Class;");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "getClass method not found");
                return JNI_ERR;
        }

        dprint("__j_ClassLoader - getClass: %p\n", __j_ClassLoader, ctx->getClass);

        ctx->getClassName = (*env)->GetMethodID(env, ctx->Class, "getName", "()Ljava/lang/String;");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "getName (Class) method not found");
                return JNI_ERR;
        }

        if (__preferred_loadable_class) {
                ctx->prefferedName = (*env)->NewStringUTF(env, __preferred_loadable_class);
                if ((*env)->ExceptionCheck(env)) {
                        PyErr_SetString(jvm_error, "NewStringUTF failed");
                        return JNI_ERR;
                }
        } else {
                ctx->prefferedName = NULL;
        }

        ctx->payload = NULL;

        return JNI_OK;
}

static
PyObject * Py_get_JVM(PyObject *self, PyObject *args) {
        if  (!__jvm) {
                PyErr_SetString(jvm_error, "JVM was not loaded yet");
                return NULL;
        }

        return PyCapsule_New(__jvm, "JVM", NULL);
}

typedef jint (*thread_enum_cb)(JNIEnv *env, jobject Thread, void *data);

static jint jvm_for_each_thread(JNIEnv *env, thread_enum_cb callback, void *data) {
        jint retval = JNI_ERR;
        void *penv = NULL;
        jclass Thread;
        jclass ThreadArray;
        jint active_threads;
        jmethodID method_activeCount;
        jmethodID method_enumerate;
        jint i;
    jobject iThread;

        if (__jvm == NULL) {
                dprint("jvm_enumerate_thread_classloaders - __jvm is not initialized\n");
                return JNI_EEXIST;
        }

        if (env == NULL) {
                retval = (*__jvm)->GetEnv(__jvm, &penv,          JNI_VERSION_1_6);
                if (retval != JNI_OK)
                        return retval;

                env = penv;
        }

        Thread = (*env)->FindClass(env, "java/lang/Thread");
        if ((*env)->ExceptionCheck(env)) {
                dprint("java/lang/Thread not found\n");
                return JNI_ERR;
        }

        ThreadArray = (*env)->FindClass(env, "[Ljava/lang/Thread;");
        if ((*env)->ExceptionCheck(env)) {
                dprint("[java/lang/Thread not found\n");
                return JNI_ERR;
        }

        method_activeCount = (*env)->GetStaticMethodID(env, Thread, "activeCount", "()I");
        if ((*env)->ExceptionCheck(env)) {
                dprint("activeCount method not found\n");
                return JNI_ERR;
        }

        method_enumerate = (*env)->GetStaticMethodID(env, Thread, "enumerate", "([Ljava/lang/Thread;)I");
        if ((*env)->ExceptionCheck(env)) {
                dprint("enumerate method not found\n");
                return JNI_ERR;
        }

        active_threads = (*env)->CallIntMethod(env, Thread, method_activeCount);
        if ((*env)->ExceptionCheck(env)) {
                dprint("activeCount() call failed\n");
                return JNI_ERR;
        }

        dprint("Active threads: %d\n", active_threads);

        ThreadArray = (*env)->NewObjectArray(env, active_threads, Thread, NULL);
        if ((*env)->ExceptionCheck(env)) {
                dprint("new Thread[%d] failed\n", active_threads);
                return JNI_ERR;
        }

        active_threads = (*env)->CallIntMethod(env, Thread, method_enumerate, ThreadArray);
        if ((*env)->ExceptionCheck(env)) {
                dprint("enumerate() call failed\n");
                return JNI_ERR;
        }

        dprint("enumerate() return %d threads\n", active_threads);

        for (i=0; i<active_threads; i++) {
                dprint("enumerate() - process %d thread\n", i);
                iThread = (*env)->GetObjectArrayElement(env, ThreadArray, i);
                if ((*env)->ExceptionCheck(env)) {
                        dprint("enumerate(): get %d element of array list failed\n", i);
                        return JNI_ERR;
                }

                dprint("enumerate() - process %d thread - class at %p, callback at %p\n",
                        i, iThread, callback);

                retval = callback(env, iThread, data);

                dprint("enumerate() - retval: %d\n");

                if (retval != JNI_OK) {
                        return retval;
                }
        }

        return JNI_OK;
}

static jint __thread_class_loader_name_and_class(
        JNIEnv *env, struct __thread_name_and_classloader_to_dict_ctx *ctx, jobject thread,
        char **name, jobject *classloader) {

        const char *utfchars = NULL;
        jobject threadContextLoader;
        jobject threadContextLoaderClass;
        jobject threadContextLoaderClassName;

        dprint("__thread_class_loader_name_and_class: 1 %p, %p\n", thread, ctx->getContextClassLoader);
        threadContextLoader = (*env)->CallObjectMethod(env, thread, ctx->getContextClassLoader);
        dprint("__thread_class_loader_name_and_class: 1.1\n");
        if ((*env)->ExceptionCheck(env)) {
                dprint("Thread.getContextClassLoader() failed\n");
                return JNI_ERR;
        }

        dprint("__thread_class_loader_name_and_class: 2\n");
        if (threadContextLoader != NULL) {
                        dprint("__thread_class_loader_name_and_class: 3\n");

                threadContextLoaderClass = (*env)->CallObjectMethod(env, threadContextLoader, ctx->getClass);
                if ((*env)->ExceptionCheck(env)) {
                        dprint("ContextLoader.getClass() failed\n");
                        return JNI_ERR;
                }

                dprint("__thread_class_loader_name_and_class: 4\n");

                threadContextLoaderClassName = (*env)->CallObjectMethod(env, threadContextLoaderClass, ctx->getClassName);
                if ((*env)->ExceptionCheck(env)) {
                        dprint("Class.getName() failed\n");
                        return JNI_ERR;
                }

                dprint("__thread_class_loader_name_and_class: 4\n");

                utfchars = (*env)->GetStringUTFChars(env, threadContextLoaderClassName, NULL);
                if ((*env)->ExceptionCheck(env)) {
                        PyErr_SetString(jvm_error, "Could not extract string from Java String");
                        return JNI_ERR;
                }
                if (name)
                        *name = strdup(utfchars);

                if (classloader)
                        *classloader = threadContextLoader;
        } else {
                if (name)
                        *name = strdup("{{ bootstrap }}");

                if (classloader)
                        *classloader = NULL;
        }

        dprint("__thread_class_loader_name_and_class: 5\n");
        return JNI_OK;
}


static jint __find_preferred_classloader_finder(JNIEnv *env, jobject thread, void *data) {
        struct __thread_name_and_classloader_to_dict_ctx *ctx = data;

        jint err = JNI_ERR;
        jobject threadName = NULL;
        jobject classLoader = NULL;
        char *classLoaderName = NULL;
        jclass loadedClass = NULL;

        if (ctx->payload != NULL) {
                return JNI_OK;
        }

        dprint("__find_preferred_classloader_finder - get thread name using %p..\n", ctx->getName);

        threadName = (*env)->CallObjectMethod(env, thread, ctx->getName);
        if ((*env)->ExceptionCheck(env)) {
                dprint("Thread.getName() failed\n");
                return JNI_ERR;
        }

        dprint("__find_preferred_classloader_finder - threadName:  %p..\n", threadName);

        err = __thread_class_loader_name_and_class(env, ctx, thread, &classLoaderName, &classLoader);
        if (err != JNI_OK) {
                return err;
        }

        dprint("__find_preferred_classloader_finder: class loader name: %s\n", classLoaderName);

        if (__preferred_classloader_name) {
                dprint("__find_preferred_classloader_finder: __preferred_classloader_name = %s\n",
                        __preferred_classloader_name);
        }

        if (__preferred_classloader_name && __preferred_classloader_name[0] != '\0' &&
                !strcmp(classLoaderName, __preferred_classloader_name)) {
                ctx->payload = classLoader;
        } else {
                // Try to findLoadedClass
                // Ignore result. If no exception, then classLoader can load requested
                // class

                if (ctx->prefferedName != NULL && classLoader != NULL) {
                        loadedClass = (*env)->CallStaticObjectMethod(
                                env, ctx->Class, ctx->forName, ctx->prefferedName, True, classLoader);
                        if ((*env)->ExceptionCheck(env) == JNI_OK) {
                                if (loadedClass) {
                                        dprint("Found classLoader for class %s: %s\n",
                                                __preferred_loadable_class, classLoaderName);
                                        ctx->payload = classLoader;
                                } else {
                                        dprint("Class %s could not be resolved with %s (%p)\n",
                                                __preferred_loadable_class, classLoaderName, classLoader);
                                }
                        } else {
                                dprint("Class %s could not be resolved with %s (%p)\n",
                                        __preferred_loadable_class, classLoaderName, classLoader);
                                (*env)->ExceptionClear(env);
                        }
                }
        }

        free(classLoaderName);
        return JNI_OK;
}


static jobject __find_preferred_classloader(JNIEnv *env) {
        struct __thread_name_and_classloader_to_dict_ctx ctx;

        if (!__jvm) {
                dprint("JVM is not initialized yet\n");
                return NULL;
        }

        if (__j_preferred_classloader != NULL)
                return __j_preferred_classloader;

        if (!((__preferred_classloader_name != NULL && __preferred_classloader_name[0] != '\0') ||
                        (__preferred_loadable_class != NULL && __preferred_loadable_class[0] != '\0')))
                goto lbDefault;

        dprint("Search for preferred classloader\n");

        if (Py_new__thread_name_and_classloader_to_dict_ctx(env, &ctx) != JNI_OK)
                goto lbDefault;

        if (jvm_for_each_thread(env, __find_preferred_classloader_finder, &ctx) != JNI_OK)
                goto lbError;

        if (ctx.payload) {
                dprint("Found preferred classloader\n");
                __j_preferred_classloader = (*env)->NewGlobalRef(env, (jobject) ctx.payload);
                return __j_preferred_classloader;
        }

  lbError:
        dprint("Couldn't find preferred classloader, use cached default\n");

  lbDefault:
        return __j_initial_classloader;
}

static
PyObject * Py_get_PreferredClassLoader(PyObject *self, PyObject *args) {
        jobject classloader = NULL;
    JNIEnv *env = NULL;
        PyObject *PyJNIEnv = NULL;

        if (__j_preferred_classloader != NULL)
                return PyCapsule_New(
                        __j_preferred_classloader, "PreferredClassLoader", NULL);

        if (!PyArg_ParseTuple(args, "O", &PyJNIEnv)) {
                return NULL;
        }

        env = PyCapsule_GetPointer(PyJNIEnv, "JNIEnv");
        if (env == NULL) {
                return NULL;
        }

        classloader = __find_preferred_classloader(env);
        if (classloader == NULL)
                return NULL;

        return PyCapsule_New(classloader, "PreferredClassLoader", NULL);
}

static jclass get_thread_class(JNIEnv *env) {
        jclass Thread;

        env = Py_get_jni_env(env);
        if (env == NULL)
                return NULL;

        Thread = (*env)->FindClass(env, "java/lang/Thread");
        if ((*env)->ExceptionCheck(env)) {
                dprint("java/lang/Thread not found\n");
                return NULL;
        }

        return Thread;
}

static jint call_method(
        JNIEnv *env, jclass klass, jobject instance,
        jboolean is_static, const char *method,
        const char *signature, jobject *result, va_list a_list) {

        jmethodID method_id;
        jint retcode = JNI_ERR;
        jobject retval = NULL;

        if (is_static == JNI_TRUE) {
                method_id = (*env)->GetStaticMethodID(
                        env, klass, method, signature);
        } else {
                method_id = (*env)->GetMethodID(
                        env, klass, method, signature);
        }

        if ((*env)->ExceptionCheck(env)) {
                dprint(
                        "call_method: method %s with signature %s not found\n",
                        method, signature);
                goto lbExit;
        }

        if (is_static) {
                retval = (*env)->CallStaticObjectMethodV(
                        env, klass, method_id, a_list);
        } else {
                retval = (*env)->CallObjectMethodV(
                        env, instance, method_id, a_list);
        }
        if ((*env)->ExceptionCheck(env)) {
                dprint("call_method: call  failed\n", method);
                goto lbExit;
        }

        if (result != NULL) {
                *result = retval;
        }

        retcode = JNI_OK;

  lbExit:
        return retcode;
}

static jint call_class_method(
        JNIEnv *env, jclass klass, const char *method,
        const char *signature, jobject *result, ...) {

        jint ret;

        va_list a_list;
        va_start(a_list, result);

        ret = call_method(
                env, klass, NULL, JNI_TRUE, method,
                signature, result, a_list
        );

        va_end(a_list);

        return ret;
}

static jint call_instance_method(
        JNIEnv *env, jobject instance, const char *method,
        const char *signature, jobject *result, ...) {

        jint ret = JNI_ERR;
        jclass klass;

        va_list a_list;
        va_start(a_list, result);

        klass = (*env)->GetObjectClass(env, instance);
        if ((*env)->ExceptionCheck(env)) {
                dprint(
                        "call_method: could not retrieve class of %p\n",
                        instance);
                goto lbExit;
        }

        ret = call_method(
                env, klass, instance, JNI_FALSE,
                method, signature, result, a_list
        );

        va_end(a_list);

  lbExit:
        return ret;
}

static PyObject* Py_JString_to_PyString(JNIEnv *env, jobject jstr) {
        const char *utfchars = (*env)->GetStringUTFChars(env, jstr, NULL);
        PyObject *result;

        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "Could not extract string from Java String");
                return NULL;
        }

        if (utfchars == NULL) {
                result = PyString_FromString("");
        } else {
                result = PyString_FromString(utfchars);
        }

        (*env)->ReleaseStringUTFChars(env, jstr, utfchars);

        return result;
}

static jint __thread_name_and_classloader_to_dict(JNIEnv *env, jobject thread, void *data) {
        struct __thread_name_and_classloader_to_dict_ctx *ctx = data;

        jint err;
        jobject threadName;
        jobject classLoader;
        char *classLoaderName;


        PyObject *Py_threadName = NULL;
        PyObject *Py_classLoaderName = NULL;

        threadName = (*env)->CallObjectMethod(env, thread, ctx->getName);
        if ((*env)->ExceptionCheck(env)) {
                dprint("Thread.getName() failed\n");
                return JNI_ERR;
        }

        err = __thread_class_loader_name_and_class(env, ctx, thread, &classLoaderName, &classLoader);
        if (err != JNI_OK) {
                return err;
        }

        Py_classLoaderName = PyString_FromString(classLoaderName);
        free(classLoaderName);

        if (Py_classLoaderName == NULL) {
                return JNI_ENOMEM;
        }

        Py_threadName = Py_JString_to_PyString(env, threadName);
        if (Py_threadName == NULL) {
                Py_DECREF(Py_classLoaderName);
                return JNI_ERR;
        }

        if (PyDict_SetItem((PyObject *) ctx->payload, Py_threadName, Py_classLoaderName) != 0) {
                Py_DECREF(Py_threadName);
                Py_DECREF(Py_classLoaderName);
                return JNI_ERR;
        }

        return JNI_OK;
}

// Search classloaders by threads
static
PyObject *Py_enumerate_threads_classloaders(PyObject *self, PyObject *args) {
        struct __thread_name_and_classloader_to_dict_ctx ctx;
        jint retval;

        JNIEnv *env = Py_get_jni_env(NULL);
        if (env == NULL) {
                return NULL;
        }

        if (Py_new__thread_name_and_classloader_to_dict_ctx(env, &ctx) != JNI_OK) {
                return NULL;
        }

        ctx.payload = (void*) PyDict_New();
        if (ctx.payload == NULL) {
                PyErr_SetString(jvm_error, "Couldn't create new dict");
                return NULL;
        }

        retval = jvm_for_each_thread(env, __thread_name_and_classloader_to_dict, &ctx);
        if (retval != JNI_OK) {
                Py_DECREF((PyObject *) ctx.payload);
                PyErr_SetString(jvm_error, "Error during threads enumeration");
                return NULL;
        }

        return (PyObject*) ctx.payload;
}


static
PyObject *Py_set_preferred_classloader_name(PyObject *self, PyObject *args) {
        char *new_classloader_name = NULL;
        JNIEnv *env = NULL;

        if (!PyArg_ParseTuple(args, "s", &new_classloader_name)) {
                return NULL;
        }

        if (__preferred_classloader_name != NULL) {
                free(__preferred_classloader_name);
                __preferred_classloader_name = NULL;
        }

        if (__j_preferred_classloader != NULL) {
                env = Py_get_jni_env(NULL);
                if (env == NULL)
                        return NULL;
                (*env)->DeleteGlobalRef(env, __j_preferred_classloader);
                __j_preferred_classloader = NULL;
        }

        if (new_classloader_name != NULL && new_classloader_name[0] != '\0') {
                __preferred_classloader_name = strdup(new_classloader_name);
        }

        if (__preferred_classloader_name)
                return PyString_FromString(__preferred_classloader_name);

        return Py_BuildValue("");
}

static
PyObject *Py_set_preferred_loadable_class(PyObject *self, PyObject *args) {
        JNIEnv* env;
        char *new_loadable_class = NULL;

        if (!PyArg_ParseTuple(args, "s", &new_loadable_class)) {
                return NULL;
        }

        if (__preferred_loadable_class != NULL) {
                free(__preferred_loadable_class);
                __preferred_loadable_class = NULL;
        }

        if (__j_preferred_classloader != NULL) {
                env = Py_get_jni_env(NULL);
                if (env == NULL)
                        return NULL;
                (*env)->DeleteGlobalRef(env, __j_preferred_classloader);
                __j_preferred_classloader = NULL;
        }

        if (new_loadable_class != NULL && new_loadable_class[0] != '\0') {
                __preferred_loadable_class = strdup(new_loadable_class);
        }

        if (__preferred_loadable_class)
                return PyString_FromString(__preferred_loadable_class);

        return Py_BuildValue("");
}

static
PyObject *Py_get_preferred_classloader_name(PyObject *self, PyObject *args) {
        if (__preferred_classloader_name != NULL)
                return PyString_FromString(__preferred_classloader_name);

        return Py_BuildValue("");
}

static
PyObject *Py_get_preferred_loadable_class(PyObject *self, PyObject *args) {
        if (__preferred_loadable_class != NULL)
                return PyString_FromString(__preferred_loadable_class);

        return Py_BuildValue("");
}

static
PyObject *Py_set_ClassLoader(PyObject *self, PyObject *args) {
        JNIEnv *env = NULL;
        jobject classloader = NULL;
        jobject currentThread = NULL;
        jobject retval;
        jclass Thread = NULL;
        jint ret;

        if (__jvm == NULL) {
                PyErr_SetString(jvm_error, "JVM was not loaded yet");
                return NULL;
        }

        env = Py_get_jni_env(NULL);
        if (!env)
                return NULL;

        dprint("Get Thread's JNIEnv: %p\n", env);

        classloader = __find_preferred_classloader(env);
        if (classloader == NULL) {
                PyErr_SetString(
                        jvm_error, "Preferred classloader was not found");
                return NULL;
        }

        dprint("Initial: JVM: %p, ClassLoader: %p\n", __jvm, classloader);

        Thread = get_thread_class(env);
        if (Thread == NULL) {
                PyErr_SetString(jvm_error, "Could not find Thread class");
                return NULL;
        }

        dprint("Get Thread class: %p\n", Thread);

        ret = call_class_method(
                env, Thread, "currentThread", "()Ljava/lang/Thread;",
                &currentThread);
        if (ret != JNI_OK) {
                PyErr_SetString(jvm_error, "Could not find current JVM Thread");
                return NULL;
        }

        dprint("Get current thread: %p\n", currentThread);

        ret = call_instance_method(
                env, currentThread, "setContextClassLoader", "(Ljava/lang/ClassLoader;)V",
                &retval, classloader);

        if (ret != JNI_OK) {
                PyErr_SetString(jvm_error, "Iteration failed");
                return NULL;
        }

        return PyBool_FromLong(1);
}


static jclass JNICALL __multi_FindClass(JNIEnv *env, const char *name) {
        jclass result = NULL;
        jstring className = NULL;

        dprint(
                "FindClass called (ICL: %p PCL: %p)\n",
                __j_initial_classloader, __j_preferred_classloader
        );

        if (__j_preferred_classloader || __j_initial_classloader) {
                dprint(
                        "Classloaders: Preferred: %p Initial: %p\n",
                        __j_preferred_classloader, __j_initial_classloader);

                className = (*env)->NewStringUTF(env, name);
                if ((*env)->ExceptionCheck(env)) {
                        dprint("FindClass mapping failed for %s\n", name);
                        return NULL;
                }
                dprint("Search %s (mapped as %p)\n", name, className);
        }

        if (className) {
                if (__j_preferred_classloader) {
                        result = (*env)->CallObjectMethod(
                                env, __j_preferred_classloader, __j_ClassLoader_findClass, className);

                        dprint("Search using preferred classloader: %s -> %p\n", name, result);

                        if ((*env)->ExceptionCheck(env)) {
                                dprint("Hooked PreferredClassloader->FindClass(%s) - failed\n", name);
                                (*env)->ExceptionClear(env);
                                result = NULL;
                        }

                        if (result != NULL) {
                                dprint("Return %p\n", result);
                                return result;
                        }
                }

                if (__j_initial_classloader) {
                        result = (*env)->CallObjectMethod(
                                env, __j_initial_classloader, __j_ClassLoader_findClass, className);

                        dprint("Search using initial classloader: %s -> %p\n", name, result);

                        if ((*env)->ExceptionCheck(env)) {
                                dprint("Hooked InitialClassloader->FindClass(%s) - failed\n", name);
                                (*env)->ExceptionClear(env);
                                result = NULL;
                        }

                        if (result != NULL) {
                                dprint("Return %p\n", result);
                                return result;
                        }
                }
        }

        dprint("Fallback to bootstrap classloader for %s\n", name);
        return (*env)->FindClass(env, name);
}

static
PyObject *Py_find_class(PyObject *self, PyObject *args) {
        PyObject *PyJNIEnv;
        JNIEnv *env;
        char *class_name;
        jclass result;

        if (!PyArg_ParseTuple(args, "Os", &PyJNIEnv, &class_name)) {
                return NULL;
        }

        env = PyCapsule_GetPointer(PyJNIEnv, "JNIEnv");
        if (env == NULL) {
                return NULL;
        }

        result = __multi_FindClass(env, class_name);
        if (result == NULL)
                return Py_BuildValue("");

        return PyCapsule_New(result, "Class", NULL);
}

static PyMethodDef JVM_Methods[] = {
        { "get_jvm", Py_get_JVM, METH_NOARGS, "Get pointer to JVM" },
        { "find_class", Py_find_class, METH_VARARGS, "Call hinted FindClass" },
        { "get_preferred_classloader", Py_get_PreferredClassLoader,
          METH_VARARGS, "Get pointer to initializer thread's ClassLoader" },
        { "set_preferred_classloader_name", Py_set_preferred_classloader_name,
          METH_VARARGS, "Class name of required default classloader" },
        { "get_preferred_classloader_name", Py_get_preferred_classloader_name,
          METH_NOARGS, "Get current class name of requried default classloader" },
        { "set_preferred_loadable_class", Py_set_preferred_loadable_class,
          METH_VARARGS, "Class name of class which required classloader should be able to load" },
        { "get_preferred_loadable_class", Py_get_preferred_loadable_class,
          METH_NOARGS, "Get current class name of class which required classloader should be able to load" },
        { "enumerate_threads_classloaders", Py_enumerate_threads_classloaders,
          METH_NOARGS, "Get dict of thread names and names of their classloaders" },
        { "apply_preferred_classloader", Py_set_ClassLoader, METH_NOARGS,
          "initializer thread's ClassLoader to current thread" },
        { NULL, NULL },		/* Sentinel */
};

static
PyObject* setup_jvm_class(void) {
        PyObject *jvm_klass = Py_InitModule3("jvm", JVM_Methods, jvm_module_doc);
        if (!jvm_klass) {
                return NULL;
        }

        jvm_error = PyErr_NewException("jvm.error", NULL, NULL);
        Py_INCREF(jvm_error);
        PyModule_AddObject(jvm_klass, "error", jvm_error);

        return jvm_klass;
}

static
void __jni_deinit(int status, void *data) {
        dprint("JVM deinitialization\n");

        if (__jvm == NULL)
                return;

        // Do nothing for now
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
        jclass Thread;
        jobject classLoader;
        JNIEnv* env;
        jobject currentThread;
        jint ret;
        JavaVMAttachArgs args;

        if (!vm) {
                return 0;
        }

        dprint("JVM provided: %p\n", vm);

        __jvm = vm;

        ret = (*vm)->GetEnv(vm, &env,  JNI_VERSION_1_6);
        if (ret != JNI_OK) {
                if (ret == JNI_EDETACHED) {
                        dprint("JVM Attach required\n");
                        ret = (*vm)->AttachCurrentThread(vm, &env, (void *)&args);
                        if (ret == JNI_OK) {
                                dprint("Attached to JVM: %s ver %08x\n", args.name, args.version);
                        }
                }

                if (ret != JNI_OK) {
                        dprint("Failed to get JNIEnv: %d\n", ret);
                        return JNI_ERR;
                }
        }

        Thread = get_thread_class(env);
        if (Thread == NULL) {
                return JNI_ERR;
        }

        ret = call_class_method(
                env, Thread, "currentThread", "()Ljava/lang/Thread;",
                &currentThread);
        if (ret != JNI_OK) {
                return ret;
        }

        dprint("Current Thread: %p\n", currentThread);

        ret = call_instance_method(
                env, currentThread, "getContextClassLoader", "()Ljava/lang/ClassLoader;",
                &classLoader);
        if (ret != JNI_OK) {
                return ret;
        }

        dprint("Current Thread ClassLoader: %p\n", classLoader);

        __j_initial_classloader = (*env)->NewGlobalRef(env, classLoader);
        if ((*env)->ExceptionCheck(env)) {
                dprint("NewGlobalRef failed");
                __j_initial_classloader = NULL;
                return JNI_ENOMEM;
        }

        dprint("New global ref to Current Thread ClassLoader: %p\n", __j_initial_classloader);

        __j_ClassLoader = (*env)->FindClass(env, "java/lang/ClassLoader");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "java/lang/ClassLoader class not found");
                return JNI_ERR;
        }

        __j_ClassLoader = (*env)->NewGlobalRef(env, __j_ClassLoader);

        dprint("Cache ClassLoader class: %p\n", __j_ClassLoader);

        __j_ClassLoader_findClass = (*env)->GetMethodID(
                env, __j_ClassLoader, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if ((*env)->ExceptionCheck(env)) {
                PyErr_SetString(jvm_error, "findClass method not found");
                return JNI_ERR;
        }

        dprint("Cache ClassLoader.findClass methodId: %p\n", __j_ClassLoader_findClass);

#ifndef _WIN32
        on_exit(__jni_deinit, NULL);
#endif

        return JNI_VERSION_1_6;
}
