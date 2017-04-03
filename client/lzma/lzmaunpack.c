/* --- Code for inlining --- */

#include "LzmaDec.h"

static void *_lzalloc(void *p, size_t size) { p = p; return malloc(size); }
static void _lzfree(void *p, void *address) { p = p; free(address); }
static ISzAlloc _lzallocator = { _lzalloc, _lzfree };

static void *lzmaunpack(const char *data, size_t size, size_t *puncompressed_size) {
	unsigned char *uncompressed = NULL;
	size_t uncompressed_size = 0;

	const Byte *wheader = (Byte *) data + sizeof(unsigned int);
	const Byte *woheader = (Byte *) wheader + LZMA_PROPS_SIZE;

	ELzmaStatus status;
	size_t srcLen;
	int res;

    union {
      unsigned int l;
      unsigned char c[4];
	} x;

    x.c[3] = data[0];
	x.c[2] = data[1];
	x.c[1] = data[2];
	x.c[0] = data[3];

	uncompressed_size = x.l;

	uncompressed = malloc(uncompressed_size);
	if (!uncompressed) {
		return NULL;
	}

	srcLen = size - sizeof(unsigned int) - LZMA_PROPS_SIZE;

	res = LzmaDecode(
		uncompressed, &uncompressed_size, woheader, &srcLen, wheader,
		LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status, &_lzallocator
	);

	if (res != SZ_OK) {
		free(uncompressed);
		return NULL;
	}

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

	free(uncompressed);
	return object;
}
