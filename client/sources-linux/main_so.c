#include <stdlib.h>
#include <pthread.h>

#include "pupy_load.h"

static void *
thread_start(void *arg)
{
	return (void *) mainThread(0, NULL);
}


__attribute__((constructor))
void loader(void) {
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_t thread_id;

	pthread_create(
		&thread_id, &attr,
		thread_start, NULL
	);
}
