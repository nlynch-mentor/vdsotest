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

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "compiler.h"
#include "vdsotest.h"

#define USEC_PER_SEC 1000000

static int gettimeofday_syscall_wrapper(struct timeval *tv, struct timezone *tz)
{
	return syscall(SYS_gettimeofday, tv, tz);
}

static int (*gettimeofday_fn)(struct timeval *tv, struct timezone *tz) =
	gettimeofday_syscall_wrapper;

static void gettimeofday_syscall_nofail(struct timeval *tv, struct timezone *tz)
{
	int err;

	err = gettimeofday_syscall_wrapper(tv, tz);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_gettimeofday");
}

static void gettimeofday_nofail(struct timeval *tv, struct timezone *tz)
{
	int err;

	err = gettimeofday_fn(tv, tz);
	if (err)
		error(EXIT_FAILURE, errno, "gettimeofday");
}

static bool timevals_ordered(const struct timeval *first,
			     const struct timeval *second)
{
	if (first->tv_sec < second->tv_sec)
		return true;

	if (first->tv_sec == second->tv_sec)
		return first->tv_usec <= second->tv_usec;

	return false;
}

static bool timeval_normalized(const struct timeval *tv)
{
	if (tv->tv_sec < 0)
		return false;
	if (tv->tv_usec < 0)
		return false;
	if (tv->tv_usec >= USEC_PER_SEC)
		return false;
	return true;
}

static void gettimeofday_verify(struct ctx *ctx)
{
	struct timeval now;

	gettimeofday_syscall_nofail(&now, NULL);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		struct timeval prev;

		prev = now;

		gettimeofday_nofail(&now, NULL);

		if (!timeval_normalized(&now)) {
			log_failure(ctx, "timestamp obtained from libc/vDSO "
				    "not normalized:\n"
				    "\t[%ld, %ld]\n",
				    now.tv_sec, now.tv_usec);
		}

		if (!timevals_ordered(&prev, &now)) {
			log_failure(ctx, "timestamp obtained from libc/vDSO "
				    "predates timestamp\n"
				    "previously obtained from kernel:\n"
				    "\t[%ld, %ld] (kernel)\n"
				    "\t[%ld, %ld] (vDSO)\n",
				    prev.tv_sec, prev.tv_usec,
				    now.tv_sec, now.tv_usec);
		}

		prev = now;

		gettimeofday_syscall_nofail(&now, NULL);

		if (!timeval_normalized(&now)) {
			log_failure(ctx, "timestamp obtained from kernel "
				    "not normalized:\n"
				    "\t[%ld, %ld]\n",
				    now.tv_sec, now.tv_usec);
		}

		if (!timevals_ordered(&prev, &now)) {
			log_failure(ctx, "timestamp obtained from kernel "
				    "predates timestamp\n"
				    "previously obtained from libc/vDSO:\n"
				    "\t[%ld, %ld] (vDSO)\n"
				    "\t[%ld, %ld] (kernel)\n",
				    prev.tv_sec, prev.tv_usec,
				    now.tv_sec, now.tv_usec);
		}

	}

	ctx_cleanup_timer(ctx);
}

static void gettimeofday_bench(struct ctx *ctx, struct bench_results *res)
{
	struct timeval tv;
	uint64_t calls;

	BENCH(ctx, gettimeofday_fn(&tv, NULL),
	      &res->vdso_interval, calls);

	BENCH(ctx, gettimeofday_syscall_wrapper(&tv, NULL),
	      &res->sys_interval, calls);
}

struct gettimeofday_args {
	struct timeval *tv;
	struct timezone *tz;
	bool force_syscall;
};

enum gtod_arg_type {
	valid,
	nullptr,
	bogus,
	prot_none,
	prot_read,
	gtod_arg_type_max,
};

static const char *gtod_arg_type_str[] = {
	[valid] = "valid",
	[nullptr] = "NULL",
	[bogus] = "UINTPTR_MAX",
	[prot_none] = "page (PROT_NONE)",
	[prot_read] = "page (PROT_READ)",
};

static void do_gettimeofday(void *arg, struct syscall_result *res)
{
	struct gettimeofday_args *args = arg;
	int err;

	syscall_prepare();
	if (args->force_syscall)
		err = gettimeofday_syscall_wrapper(args->tv, args->tz);
	else
		err = gettimeofday_fn(args->tv, args->tz);
	record_syscall_result(res, err, errno);
}

static void *gtod_arg_alloc(enum gtod_arg_type t)
{
	void *ret;

	switch (t) {
	case valid:
		ret = xmalloc(sysconf(_SC_PAGESIZE));
		break;
	case nullptr:
		ret = NULL;
		break;
	case bogus:
		ret = (void *)ADDR_SPACE_END;
		break;
	case prot_none:
		ret = alloc_page(PROT_NONE);
		break;
	case prot_read:
		ret = alloc_page(PROT_READ);
		break;
	default:
		assert(false);
		break;
	}

	return ret;
}

static void gtod_arg_release(void *buf, enum gtod_arg_type t)
{
	switch (t) {
	case valid:
		xfree(buf);
		break;
	case nullptr:
	case bogus:
		break;
	case prot_none:
	case prot_read:
		free_page(buf);
		break;
	default:
		assert(false);
		break;
	}
}

static bool __pure gtod_args_should_fault(enum gtod_arg_type tv,
					  enum gtod_arg_type tz)
{
	switch (tv) {
	case valid:
	case nullptr:
		break;
	case bogus:
	case prot_none:
	case prot_read:
		return true;
		break;
	default:
		assert(false);
		break;
	}

	switch (tz) {
	case valid:
	case nullptr:
		break;
	case bogus:
	case prot_none:
	case prot_read:
		return true;
		break;
	default:
		assert(false);
		break;
	}

	return false;
}

static void gettimeofday_abi(struct ctx *ctx)
{
	enum gtod_arg_type tv_type;

	for (tv_type = 0; tv_type < gtod_arg_type_max; tv_type++) {
		enum gtod_arg_type tz_type;
		struct timeval *tv;

		tv = gtod_arg_alloc(tv_type);

		for (tz_type = 0; tz_type < gtod_arg_type_max; tz_type++) {
			struct gettimeofday_args args;
			struct signal_set signal_set;
			struct child_params parms;
			struct timezone *tz;
			int expected_errno;
			int expected_ret;
			char *desc;

			tz = gtod_arg_alloc(tz_type);

			/* First, force system call */
			args = (struct gettimeofday_args) {
				.tv = tv,
				.tz = tz,
				.force_syscall = true,
			};

			expected_ret = 0;
			if (gtod_args_should_fault(tv_type, tz_type))
				expected_ret = -1;

			expected_errno = 0;
			if (gtod_args_should_fault(tv_type, tz_type))
				expected_errno = EFAULT;

			/* Should never actually terminate by signal
			 * for syscall.
			 */
			signal_set.mask = 0;

			xasprintf(&desc, "SYS_gettimeofday(%s, %s)",
				  gtod_arg_type_str[tv_type],
				  gtod_arg_type_str[tz_type]);

			parms = (struct child_params) {
				.desc = desc,
				.func = do_gettimeofday,
				.arg = &args,
				.expected_ret = expected_ret,
				.expected_errno = expected_errno,
				.signal_set = signal_set,
			};

			run_as_child(ctx, &parms);

			xfree(desc);

			/* Now do libc/vDSO */

			args.force_syscall = false;
			if (gtod_args_should_fault(tv_type, tz_type))
				signal_set.mask |= SIGNO_TO_BIT(SIGSEGV);

			xasprintf(&desc, "gettimeofday(%s, %s)",
				  gtod_arg_type_str[tv_type],
				  gtod_arg_type_str[tz_type]);

			parms.desc = desc;
			parms.signal_set = signal_set;

			run_as_child(ctx, &parms);

			xfree(desc);

			gtod_arg_release(tz, tz_type);
		}

		gtod_arg_release(tv, tv_type);
	}
}

static void gettimeofday_notes(struct ctx *ctx)
{
	if (gettimeofday_fn == gettimeofday_syscall_wrapper)
		printf("Note: vDSO version of gettimeofday not found\n");
}

static const char *gettimeofday_vdso_names[] = {
	"__kernel_gettimeofday",
	"__vdso_gettimeofday",
	NULL,
};

static void gettimeofday_bind(void *sym)
{
	gettimeofday_fn = sym;
}

static const struct test_suite gettimeofday_ts = {
	.name = "gettimeofday",
	.bench = gettimeofday_bench,
	.verify = gettimeofday_verify,
	.abi = gettimeofday_abi,
	.notes = gettimeofday_notes,
	.vdso_names = gettimeofday_vdso_names,
	.bind = gettimeofday_bind,
};

static void __constructor gettimeofday_init(void)
{
	register_testsuite(&gettimeofday_ts);
}
