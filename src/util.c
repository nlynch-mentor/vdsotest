#include <assert.h>
#include <search.h>
#include <stdlib.h>
#include <string.h>

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
