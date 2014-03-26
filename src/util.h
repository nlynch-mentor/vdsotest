#ifndef VDSOTEST_UTIL_H
#define VDSOTEST_UTIL_H

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

void *xmalloc(size_t sz);
void *xzmalloc(size_t sz);
void *xrealloc(void *ptr, size_t sz);
void xfree(void *ptr);
#endif
