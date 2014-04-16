#include <assert.h>
#include <dlfcn.h>
#include <search.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util.h"

#define HASHTABLE_SZ 32

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

int xasprintf(char **strp, const char *fmt, ...)
{
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vasprintf(strp, fmt, args);
	va_end(args);

	if (ret == -1)
		abort();

	return ret;
}

static void hashtable_init(struct hashtable *ht)
{
	struct hsearch_data *htab;

	assert(!ht->htab);

	htab = xzmalloc(sizeof(*htab));

	if (!hcreate_r(HASHTABLE_SZ, htab))
		abort();

	ht->htab = htab;
}

void *hashtable_lookup(struct hashtable *ht, const char *key)
{
	ENTRY search;
	ENTRY *res;

	if (!ht->htab)
		hashtable_init(ht);

	search = (ENTRY) {
		.key = (void *)key,
	};

	hsearch_r(search, FIND, &res, ht->htab);

	return res ? res->data : NULL;
}

void hashtable_add(struct hashtable *ht, const char *key, const void *data)
{
	ENTRY search;
	ENTRY *res;

	if (!ht->htab)
		hashtable_init(ht);

	assert(!hashtable_lookup(ht, key));

	search = (ENTRY) {
		.key = (void *)key,
		.data = (void *)data,
	};

	if (!hsearch_r(search, ENTER, &res, ht->htab))
		abort();
}

void *alloc_page(int prot)
{
	void *ret;
	int flags;

	flags = MAP_PRIVATE | MAP_ANONYMOUS;

	ret = mmap(NULL, sysconf(_SC_PAGESIZE), prot, flags, -1, 0);
	if (ret == MAP_FAILED)
		abort();

	return ret;
}

void free_page(void *page)
{
	int err;

	err = munmap(page, sysconf(_SC_PAGESIZE));
	if (err)
		abort();
}

void *get_vdso_sym(const char *name)
{
	void *handle;
	void *sym;

	handle = dlopen("linux-vdso.so.1", RTLD_NOW | RTLD_GLOBAL);
	if (!handle)
		handle = dlopen("linux-gate.so.1", RTLD_NOW | RTLD_GLOBAL);

	if (handle) {
		(void)dlerror();
		sym = dlsym(handle, name);
		if (dlerror())
			sym = NULL;
	} else {
		sym = NULL;
	}

	return sym;
}
