/*
 * Copyright 2014 Mentor Graphics Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef VDSOTEST_UTIL_H
#define VDSOTEST_UTIL_H

#include <search.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "compiler.h"

#define NSEC_PER_SEC 1000000000L

#define ADDR_SPACE_END UINTPTR_MAX

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef __powerpc__

#define IS_VDSO_ERR(rval, err) (err & (1 << 28))

#define VDSO_ERR(rval,err) rval

/*
 * GPLv2 or later glibc macro used here and intentionally kept similar
 * so at to not diverge to ease any future merging.
 * Start glibc/sysdeps/unix/sysv/linux/powerpc/powerpc64/sysdep.h
 */
#define VDSO_CALL(funcptr, err, type, nr, args...)                  \
	({                                                              \
	register void *r0  __asm__ ("r0");                              \
	register long int r3  __asm__ ("r3");                           \
	register long int r4  __asm__ ("r4");                           \
	register long int r5  __asm__ ("r5");                           \
	register long int r6  __asm__ ("r6");                           \
	register long int r7  __asm__ ("r7");                           \
	register long int r8  __asm__ ("r8");                           \
	register type rval  __asm__ ("r3");                             \
	LOADARGS_##nr (funcptr, args);                                  \
	__asm__ __volatile__                                            \
	("mtctr %0\n\t"                                                 \
	 "bctrl\n\t"                                                    \
	 "mfcr  %0\n\t"                                                 \
	    : "+r" (r0), "+r" (r3), "+r" (r4), "+r" (r5), "+r" (r6),    \
	      "+r" (r7), "+r" (r8)                                      \
	    :                                                           \
	    : "r9", "r10", "r11", "r12", "cr0", "ctr", "lr", "memory"); \
	err = (long int) r0;                                            \
	__asm__ __volatile__ ("" : "=r" (rval) : "r" (r3));             \
	rval;                                                           \
	})

#define LOADARGS_0(name, dummy)                                     \
	r0 = name
#define LOADARGS_1(name, __arg1)                                    \
	long int arg1 = (long int) (__arg1);                            \
	LOADARGS_0(name, 0);                                            \
	r3 = arg1
#define LOADARGS_2(name, __arg1, __arg2)                            \
	long int arg2 = (long int) (__arg2);                            \
	LOADARGS_1(name, __arg1);                                       \
	r4 = arg2

/*
 *  End glibc/sysdeps/unix/sysv/linux/powerpc/powerpc64/sysdep.h
 */

#else

/* This retains current bevaiour which may be very x86 centric */

/*
 * Calling the vDSO directly instead of through libc can lead to:
 * - The vDSO code punts to the kernel (e.g. unrecognized clock id).
 * - The kernel returns an error (e.g. -22 (-EINVAL)) So we need to
 *   recognize this situation and fix things up.  Fortunately we're
 *   dealing only with syscalls that return -ve values on error.
 */

#define IS_VDSO_ERR(rval, err) (rval < 0)

#define VDSO_ERR(rval, err) -err

#define VDSO_CALL(funcptr, err, type, nr, args...) \
	err = funcptr(args)

#endif

#define DO_VDSO_CALL(funcptr, type, nr, args...)    \
	({                                              \
	long int err;                                   \
	type v_ret;                                     \
	v_ret = VDSO_CALL(funcptr, err, type, nr, args); \
	if (IS_VDSO_ERR(v_ret, err)) {                  \
		errno = VDSO_ERR(v_ret, err);               \
		v_ret = -1;                                 \
	}                                               \
	v_ret;                                          \
	})

void *xmalloc(size_t sz);
void *xzmalloc(size_t sz);
void *xrealloc(void *ptr, size_t sz);
void xfree(void *ptr);
int xasprintf(char **strp, const char *fmt, ...) __printf(2, 3);

struct hashtable {
	struct hsearch_data *htab;
};

void *hashtable_lookup(struct hashtable *ht, const char *key);
void hashtable_add(struct hashtable *ht, const char *key, const void *data);

static inline uint64_t timespec_to_nsec(const struct timespec *ts)
{
	uint64_t res;

	res = NSEC_PER_SEC * (unsigned long long)ts->tv_sec;
	res += ts->tv_nsec;

	return res;
}

static inline struct timespec nsec_to_timespec(uint64_t nsec)
{
	struct timespec ret;

	ret = (struct timespec) {
		.tv_sec = nsec / NSEC_PER_SEC,
		.tv_nsec = nsec % NSEC_PER_SEC,
	};

	return ret;
}

static inline uint64_t
timespec_delta_nsec(const struct timespec *before_ts,
		    const struct timespec *after_ts)
{
	uint64_t before;
	uint64_t after;

	before = timespec_to_nsec(before_ts);
	after = timespec_to_nsec(after_ts);

	return after - before;
}

static inline struct timespec
timespec_delta(const struct timespec *before_ts,
	       const struct timespec *after_ts)
{
	return nsec_to_timespec(timespec_delta_nsec(before_ts, after_ts));
}

void *alloc_page(int prot);
void free_page(void *page);

struct signal_set {
	uint64_t mask;
};

#define SIGNO_TO_BIT(n) (1 << (n))

static inline bool signal_in_set(const struct signal_set *set, int sig)
{
	return set->mask & SIGNO_TO_BIT(sig);
}

void *get_vdso_sym(const char *name);

#endif
