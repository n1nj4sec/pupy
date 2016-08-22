#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>

#include "list.h"
#include "tmplibrary.h"
#include "debug.h"

/*

  So.. We don't want to bother with reflective bla-bla-bla. Just
  upload buffer to temporary file, load it as a library using standard
  glibc calls, then delete

*/

static inline
const char *gettemptpl() {
	static const char *templates[] = {
		"/dev/shm/XXXXXXXX",
		"/tmp/XXXXXXXX",
		"/var/tmp/XXXXXXXX",
		NULL
	};

	static const char *tmpdir = NULL;
	if (! tmpdir) {
		int i;
		for (i=0; templates[i]; i++) {
			char *buf = alloca(strlen(templates[i]+1));
			strcpy(buf, templates[i]);
			int fd = mkstemp(buf);
			if (fd != -1) {
				unlink(buf);
				close(fd);
				tmpdir = templates[i];
				break;
			}
			dprint("TRY: %s -> %d (%m)\n", buf, fd);

		}
		if (!tmpdir) {
			abort();
		}
	}

	return tmpdir;
}

typedef struct library {
	const char *name;
	void *base;
} library_t;

bool search_library(void *pState, void *pData) {
	library_t *search = (library_t *) pState;
	library_t *current = (library_t *) pData;

	if (!strcmp(search->name, current->name)) {
		search->base = current->base;
		dprint("FOUND! %s = %p\n", search->name, search->base);

		return true;
	}

	return false;
}

void *memdlopen(const char *soname, const char *buffer, size_t size) {
	dprint("memdlopen(\"%s\", %p, %ull)\n", soname, buffer, size);

	static PLIST libraries = NULL;
	if (!libraries) {
		libraries = list_create();
	}

	library_t search = {
		.name = soname,
		.base = NULL,
	};

	if (list_enumerate(libraries, search_library, &search)) {
		dprint("SO %s FOUND: %p\n", search.name, search.base);
		return search.base;
	}

	void *base = dlopen(soname, RTLD_NOW);
	if (base) {
		return base;
	}

	const char *template = gettemptpl();
	char *buf = alloca(strlen(template)+1);
	strcpy(buf, template);

	int fd = mkstemp(buf);
	if (fd == -1) {
		abort();
	}

	while (size > 0) {
		size_t n = write(fd, buffer, size);
		if (n == -1) {
			dprint("Write failed: %d left, error = %m, buffer = %p, tmpfile = %s\n", size, buffer, buf);
			abort();
		}
		buffer += n;
		size -= n;
	}
	close(fd);

	base = dlopen(buf, RTLD_NOW);
	if (!base) {
		dprint("Couldn't load library %s: %m\n", soname);
		return NULL;
	}

	library_t *record = (library_t *) malloc(sizeof(library_t));
	record->name = strdup(soname);
	record->base = base;

	dprint("Library %s loaded to %p\n", soname, base);

	list_add(libraries, record);

	unlink(buf);

	return base;
}
