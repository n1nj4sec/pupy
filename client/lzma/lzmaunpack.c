/* --- Code for inlining --- */

#ifndef UNCOMPRESSED
#include "LzmaDec.h"

#ifdef _WIN32
#define ALLOC(x) VirtualAlloc(NULL, x, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define FREE(x, size) VirtualFree(x, 0, MEM_RELEASE)
#define INVALID_ALLOC NULL
#else
#include <sys/mman.h>
#define ALLOC(size) mmap(NULL, size + (4096 - size%4096), PROT_WRITE	\
						 | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#define FREE(x, size) munmap(x, size + (4096 - size%4096))
#define INVALID_ALLOC MAP_FAILED
#endif

static void *_lzalloc(void *p, size_t size) { p = p; return malloc(size); }
static void _lzfree(void *p, void *address) { p = p; free(address); }
static ISzAlloc _lzallocator = { _lzalloc, _lzfree };
#define lzmafree(x, size) do { FREE(x, size);}  while (0)

#else
#define lzmafree(x, size) do {} while (0)
#endif


static unsigned int charToUInt(const char *data) {
    union {
      unsigned int l;
      unsigned char c[4];
	} x;

    x.c[3] = data[0];
	x.c[2] = data[1];
	x.c[1] = data[2];
	x.c[0] = data[3];

	return x.l;
}

static void *lzmaunpack(const char *data, size_t size, size_t *puncompressed_size) {
	unsigned char *uncompressed = NULL;
	size_t uncompressed_size = 0;

#ifndef UNCOMPRESSED
	const Byte *wheader = (Byte *) data + sizeof(unsigned int);
	const Byte *woheader = (Byte *) wheader + LZMA_PROPS_SIZE;

	ELzmaStatus status;

	size_t srcLen;
	int res;
#endif

	uncompressed_size = charToUInt(data);

#ifndef UNCOMPRESSED
	uncompressed = ALLOC(uncompressed_size);
	if (uncompressed == INVALID_ALLOC) {
		return NULL;
	}

	srcLen = size - sizeof(unsigned int) - LZMA_PROPS_SIZE;

	res = LzmaDecode(
		uncompressed, &uncompressed_size, woheader, &srcLen, wheader,
		LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status, &_lzallocator
	);

	if (res != SZ_OK) {
		FREE(uncompressed, uncompressed_size);
		return NULL;
	}
#else
	uncompressed = data + sizeof(unsigned int);
#endif

	if (puncompressed_size) {
		*puncompressed_size = uncompressed_size;
	}

	return uncompressed;
}

static PyObject *PyObject_lzmaunpack(const char *data, size_t size) {
	PyObject * object;
	size_t uncompressed_size = 0;
	void *uncompressed = lzmaunpack(data, size, &uncompressed_size);
	if (!uncompressed) {
		return NULL;
	}

	object = PyMarshal_ReadObjectFromString(
		uncompressed, uncompressed_size);

	lzmafree(uncompressed, uncompressed_size);
	return object;
}

static PyObject *PyDict_lzmaunpack(const char *data, size_t size) {
	PyObject * object = NULL;

	unsigned int keys;
	unsigned int ksize, vsize, i;

	size_t offset;

	PyObject *k = NULL;
	PyObject *v = NULL;

	size_t uncompressed_size = 0;
	void *uncompressed = lzmaunpack(data, size, &uncompressed_size);
	if (!uncompressed) {
		return NULL;
	}

	object = PyDict_New();
	if (!object) {
		goto lbExit;
	}

	keys = charToUInt(uncompressed);

	for (i=0, offset=4; i<keys; i++) {
		ksize = charToUInt((char *) uncompressed + offset + 0);
		vsize = charToUInt((char *) uncompressed + offset + 4);

		offset += 8;

		k = PyString_FromStringAndSize((char *) uncompressed + offset, ksize);
		offset += ksize;

		v = PyString_FromStringAndSize((char *) uncompressed + offset, vsize);
		offset += vsize;

		if (!k || !v) {
			Py_XDECREF(k);
			Py_XDECREF(v);
			Py_XDECREF(object);
			object = NULL;
			goto lbExit;
		}

		PyDict_SetItem(object, k, v);
		Py_DECREF(k);
		Py_DECREF(v);
	}

 lbExit:
	lzmafree(uncompressed, uncompressed_size);
	return object;
}
