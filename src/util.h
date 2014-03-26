#ifndef VDSOTEST_UTIL_H
#define VDSOTEST_UTIL_H

#include <search.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

void *xmalloc(size_t sz);
void *xzmalloc(size_t sz);
void *xrealloc(void *ptr, size_t sz);
void xfree(void *ptr);

struct hashtable {
	struct hsearch_data *htab;
};

void *hashtable_lookup(struct hashtable *ht, const char *key);
void hashtable_add(struct hashtable *ht, const char *key, const void *data);

#endif
