#include <stdlib.h>

#include "util.h"

void *xmalloc(size_t sz)
{
	void *ret;

	ret = malloc(sz);
	if (!ret)
		abort();

	return ret;
}

void *xzmalloc(size_t sz)
{
	return memset(xmalloc(sz), 0, sz);
}

void *xrealloc(void *ptr, size_t sz)
{
	void *ret;

	ret = realloc(ptr, sz);
	if (!ret)
		abort();

	return ret;
}

void xfree(void *ptr)
{
	free(ptr);
}
