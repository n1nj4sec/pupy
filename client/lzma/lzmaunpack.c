/* --- Code for inlining --- */

#ifndef UNCOMPRESSED
#include "LzmaDec.h"

#ifdef _WIN32
#define ALLOC(x) VirtualAlloc(NULL, x, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define FREE(x) VirtualFree(x, 0, MEM_RELEASE)
#else
#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#endif

static void *_lzalloc(void *p, size_t size) { p = p; return malloc(size); }
static void _lzfree(void *p, void *address) { p = p; free(address); }
static ISzAlloc _lzallocator = { _lzalloc, _lzfree };
#define lzmafree(x, size) do { memset(x, 0x0, size); FREE(x);} while (0)

#else
#define lzmafree(x, size) do {} while (0)
#endif

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

    union {
      unsigned int l;
      unsigned char c[4];
	} x;

    x.c[3] = data[0];
	x.c[2] = data[1];
	x.c[1] = data[2];
	x.c[0] = data[3];

	uncompressed_size = x.l;

#ifndef UNCOMPRESSED
	uncompressed = ALLOC(uncompressed_size);
	if (!uncompressed) {
		return NULL;
	}

	srcLen = size - sizeof(unsigned int) - LZMA_PROPS_SIZE;

	res = LzmaDecode(
		uncompressed, &uncompressed_size, woheader, &srcLen, wheader,
		LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status, &_lzallocator
	);

	if (res != SZ_OK) {
		FREE(uncompressed);
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
