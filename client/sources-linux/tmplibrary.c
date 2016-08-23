#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
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
		"/dev/shm/XXXXXX",
		"/tmp/XXXXXX",
		"/var/tmp/XXXXXX",
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

bool drop_library(char *path, size_t path_size, const char *buffer, size_t size) {
	const char *template = gettemptpl();

	if (path_size < strlen(template))
		return false;

	strcpy(path, template);

	int fd = mkstemp(path);
	if (fd == -1) {
		return false;
	}

	while (size > 0) {
		size_t n = write(fd, buffer, size);
		if (n == -1) {
			dprint("Write failed: %d left, error = %m, buffer = %p, tmpfile = %s\n", size, buffer, path);
			abort();
		}
		buffer += n;
		size -= n;
	}
	close(fd);

	return true;
}

void *memdlopen(const char *soname, const char *buffer, size_t size, int flags) {
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

	void *base = dlopen(soname, RTLD_NOLOAD);
	if (base) {
		dprint("Library \"%s\" loaded from OS\n", soname);
		return base;
	}

	char buf[PATH_MAX]={};
	if (!drop_library(buf, PATH_MAX, buffer, size)) {
		dprint("Couldn't drop library %s: %m\n", soname);
		return NULL;
	}

	dprint("Library \"%s\" dropped to \"%s\"\n", soname, buf);

	base = dlopen(buf, flags);
	if (!base) {
		dprint("Couldn't load library %s (%s): %s\n", soname, buf, dlerror());
#ifndef DEBUG
		unlink(buf);
#endif
		return NULL;
	}

	dprint("Library %s loaded to %p\n", soname, base);

	library_t *record = (library_t *) malloc(sizeof(library_t));
	record->name = strdup(soname);
	record->base = base;
	list_add(libraries, record);

#ifndef DEBUG
	unlink(buf);
#endif

	return base;
}
