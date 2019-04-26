#include "jni.h"
#include "debug.h"

// TODO: Add proper deinitialization..

static JavaVM *__jvm = NULL;
static jobject __jclassloader = NULL;
static PyObject * jvm_error = NULL;
static char *__preferred_classloader_name = NULL;
static char jvm_module_doc[] = "Info about parent JVM";

struct __thread_name_and_classloader_to_dict_ctx {
	void* payload;

	jclass Thread;
	jclass ClassLoader;
	jclass Class;

	jmethodID getName;
	jmethodID getContextClassLoader;
	jmethodID getSystemClassLoader;
	jmethodID getClass;
	jmethodID getClassName;
};

static inline JNIEnv* Py_get_jni_env(JNIEnv *env) {
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

	ctx->Class = (*env)->FindClass(env, "java/lang/Class");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "java/lang/Class class not found");
		return JNI_ERR;
	}

	ctx->ClassLoader = (*env)->FindClass(env, "java/lang/ClassLoader");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "java/lang/ClassLoader class not found");
		return JNI_ERR;
	}

	ctx->getName = (*env)->GetMethodID(env, ctx->Thread, "getName", "()Ljava/lang/String;");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "getName method not found");
		return JNI_ERR;
	}

	ctx->getContextClassLoader = (*env)->GetMethodID(
		env, ctx->Thread, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "getContextClassLoader method not found");
		return JNI_ERR;
	}

	ctx->getSystemClassLoader = (*env)->GetStaticMethodID(
		env, ctx->ClassLoader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "getSystemClassLoader method not found");
		return JNI_ERR;
	}

	ctx->getClass = (*env)->GetMethodID(env, ctx->ClassLoader, "getClass", "()Ljava/lang/Class;");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "getClass method not found");
		return JNI_ERR;
	}

	ctx->getClassName = (*env)->GetMethodID(env, ctx->Class, "getName", "()Ljava/lang/String;");
	if ((*env)->ExceptionCheck(env)) {
		PyErr_SetString(jvm_error, "getName (Class) method not found");
		return JNI_ERR;
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

	if (__jvm == NULL) {
		dprint("jvm_enumerate_thread_classloaders - __jvm is not initialized\n");
		return JNI_EEXIST;
	}

	if (env == NULL) {
		retval = (*__jvm)->GetEnv(__jvm, &penv,  JNI_VERSION_1_6);
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
		jobject iThread = (*env)->GetObjectArrayElement(env, ThreadArray, i);
		if ((*env)->ExceptionCheck(env)) {
			dprint("get %d element of array list failed\n", i);
			return JNI_ERR;
		}

		dprint("enumerate() - process %d thread - class at %p, callback at %p\n",
			iThread, callback);

		retval = callback(env, iThread, data);
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

	threadContextLoader = (*env)->CallObjectMethod(env, thread, ctx->getContextClassLoader);
	if ((*env)->ExceptionCheck(env)) {
		dprint("Thread.getContextClassLoader() failed\n");
		return JNI_ERR;
	}

	if (threadContextLoader == NULL) {
		// System class loader
		threadContextLoaderClass = (*env)->CallObjectMethod(
			env, ctx->ClassLoader, ctx->getSystemClassLoader);
		if ((*env)->ExceptionCheck(env)) {
			dprint("ContextLoader.getSystemClassLoader() failed\n");
			return JNI_ERR;
		}
	}

	if (threadContextLoader != NULL) {
		threadContextLoaderClass = (*env)->CallObjectMethod(env, threadContextLoader, ctx->getClass);
		if ((*env)->ExceptionCheck(env)) {
			dprint("ContextLoader.getClass() failed\n");
			return JNI_ERR;
		}

		threadContextLoaderClassName = (*env)->CallObjectMethod(env, threadContextLoaderClass, ctx->getClassName);
		if ((*env)->ExceptionCheck(env)) {
			dprint("Class.getName() failed\n");
			return JNI_ERR;
		}

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

	return JNI_OK;
}


static jint __find_preferred_classloader_finder(JNIEnv *env, jobject thread, void *data) {
	struct __thread_name_and_classloader_to_dict_ctx *ctx = data;

	jint err;
	jobject threadName;
	jobject classLoader;
	char *classLoaderName;

	if (ctx->payload != NULL) {
		return JNI_OK;
	}

	threadName = (*env)->CallObjectMethod(env, thread, ctx->getName);
	if ((*env)->ExceptionCheck(env)) {
		dprint("Thread.getName() failed\n");
		return JNI_ERR;
	}

	err = __thread_class_loader_name_and_class(env, ctx, thread, &classLoaderName, &classLoader);
	if (err != JNI_OK) {
		return err;
	}

	if (!strcmp(classLoaderName, __preferred_classloader_name)) {
		ctx->payload = classLoader;
	}

	free(classLoaderName);
	return JNI_OK;
}


static inline jobject __find_preferred_classloader(JNIEnv *env) {
	struct __thread_name_and_classloader_to_dict_ctx ctx;

	if (!__jvm) {
		dprint("JVM is not initialized yet\n");
		return NULL;
	}

	if (__preferred_classloader_name == NULL || __preferred_classloader_name[0] == '\0') {
		// Return initial classloader
		return __jclassloader;
	}

	dprint("Search for preferred classloader\n");

	if (Py_new__thread_name_and_classloader_to_dict_ctx(env, &ctx) != JNI_OK) {
		return NULL;
	}

	if (jvm_for_each_thread(env, __find_preferred_classloader_finder, &ctx) != JNI_OK) {
		return NULL;
	}

	if (ctx.payload) {
		dprint("Found classloader for %s\n", __preferred_classloader_name);
		return (jobject) ctx.payload;
	}

	dprint("Couldn't find classloader for %s\n", __preferred_classloader_name);
	return __jclassloader;
}

static
PyObject * Py_get_PreferredClassLoader(PyObject *self, PyObject *args) {
	jobject classloader = NULL;

	if  (!__jvm) {
		PyErr_SetString(jvm_error, "JVM was not loaded yet");
		return NULL;
	}

	JNIEnv *env = Py_get_jni_env(NULL);
	if (env == NULL)
		return NULL;

	classloader = __find_preferred_classloader(env);
	if (classloader == NULL)
		return NULL;

	return PyCapsule_New(__jclassloader, "PreferredClassLoader", NULL);
}

static inline jclass get_thread_class(JNIEnv *env) {
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

static inline jint call_method(
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

	retval = (*env)->CallObjectMethodV(
		env, is_static? klass : instance, method_id, a_list);
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

static inline jint call_class_method(
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

static inline jint call_instance_method(
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

	if (!PyArg_ParseTuple(args, "s", &new_classloader_name)) {
		return NULL;
	}

	if (__preferred_classloader_name != NULL) {
		free(__preferred_classloader_name);
		__preferred_classloader_name = NULL;
	}

	if (new_classloader_name != NULL && new_classloader_name[0] != '\0') {
		__preferred_classloader_name = strdup(new_classloader_name);
	}

	return PyString_FromString(new_classloader_name);
}

static
PyObject *Py_get_preferred_classloader_name(PyObject *self, PyObject *args) {
	char *new_classloader_name = NULL;

	if (new_classloader_name != NULL && new_classloader_name[0] != '\0') {
		return Py_BuildValue("");
	}

	return PyString_FromString(new_classloader_name);
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

static PyMethodDef JVM_Methods[] = {
	{ "get_jvm", Py_get_JVM, METH_NOARGS, "Get pointer to JVM" },
	{ "get_preferred_classloader", Py_get_PreferredClassLoader,
	  METH_NOARGS, "Get pointer to initializer thread's ClassLoader" },
	{ "set_preferred_classloader_name", Py_set_preferred_classloader_name,
	  METH_VARARGS, "Class name of required default classloader" },
	{ "get_preferred_classloader_name", Py_get_preferred_classloader_name,
	  METH_NOARGS, "Get current class name of requried default classloader" },
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

JNIEXPORT
int JNI_OnLoad(JavaVM *vm, void *reserved) {
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

	__jclassloader = (*env)->NewGlobalRef(env, classLoader);
	if ((*env)->ExceptionCheck(env)) {
		dprint("NewGlobalRef failed");
		__jclassloader = NULL;
		return JNI_ENOMEM;
	}

	dprint("New global ref to Current Thread ClassLoader: %p\n", __jclassloader);

	on_exit(__jni_deinit, NULL);

	return JNI_VERSION_1_6;
}
