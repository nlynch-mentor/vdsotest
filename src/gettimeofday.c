#include <errno.h>
#include <error.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "compiler.h"
#include "vdsotest.h"

#define USEC_PER_SEC 1000000

static void gettimeofday_syscall_nofail(struct timeval *tv)
{
	int err;

	err = syscall(SYS_gettimeofday, tv, NULL);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_gettimeofday");
}

static void gettimeofday_libc_nofail(struct timeval *tv)
{
	int err;

	err = gettimeofday(tv, NULL);
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

	gettimeofday_syscall_nofail(&now);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		struct timeval prev;

		prev = now;

		gettimeofday_libc_nofail(&now);

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

		gettimeofday_syscall_nofail(&now);

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
}

static void gettimeofday_bench(struct ctx *ctx, struct bench_results *res)
{
	struct timeval tv;
	uint64_t calls;

	ctx_start_timer(ctx);

	bench_interval_begin(&res->vdso_interval, calls);

	while (!test_should_stop(ctx)) {
		gettimeofday(&tv, NULL);
		calls++;
	}

	bench_interval_end(&res->vdso_interval, calls);

	ctx_start_timer(ctx);

	bench_interval_begin(&res->sys_interval, calls);

	while (!test_should_stop(ctx)) {
		syscall(SYS_gettimeofday, &tv, NULL);
		calls++;
	}

	bench_interval_end(&res->sys_interval, calls);
}

struct gettimeofday_args {
	struct timeval *tv;
	struct timezone *tz;
};

struct timezone gtod_args_tz;
struct timeval gtod_args_tv;

static struct gettimeofday_args both_null;
static struct gettimeofday_args tz_null = { .tv = &gtod_args_tv, };
static struct gettimeofday_args tv_null = { .tz = &gtod_args_tz, };

static void sys_gettimeofday_simple(void *arg, struct syscall_result *res)
{
	struct gettimeofday_args *args = arg;
	int err;

	syscall_prepare();
	err = syscall(SYS_gettimeofday, args->tv, args->tz);
	record_syscall_result(res, err, errno);
}

static void gettimeofday_simple(void *arg, struct syscall_result *res)
{
	struct gettimeofday_args *args = arg;
	int err;

	syscall_prepare();
	err = gettimeofday(args->tv, args->tz);
	record_syscall_result(res, err, errno);
}

static const struct child_params gettimeofday_abi_params[] = {
	/* Kernel sanity checks */
	{
		.desc = "SYS_gettimeofday(NULL, NULL)",
		.func = sys_gettimeofday_simple,
		.arg = &both_null,
	},
	{
		.desc = "SYS_gettimeofday(tv, NULL)",
		.func = sys_gettimeofday_simple,
		.arg = &tz_null,
	},
	{
		.desc = "SYS_gettimeofday(NULL, tz)",
		.func = sys_gettimeofday_simple,
		.arg = &tv_null,
	},

	/* The below may be serviced by a vDSO, but not necessarily. */
	{
		.desc = "gettimeofday(NULL, NULL)",
		.func = gettimeofday_simple,
		.arg = &both_null,
	},
	{
		.desc = "gettimeofday(tv, NULL)",
		.func = gettimeofday_simple,
		.arg = &tz_null,
	},
	{
		.desc = "gettimeofday(NULL, tz)",
		.func = gettimeofday_simple,
		.arg = &tv_null,
	},
};

static void gettimeofday_abi(struct ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(gettimeofday_abi_params); i++)
		run_as_child(ctx, &gettimeofday_abi_params[i]);
}

static const struct test_suite gettimeofday_ts = {
	.name = "gettimeofday",
	.bench = gettimeofday_bench,
	.verify = gettimeofday_verify,
	.abi = gettimeofday_abi,
};

static void __constructor gettimeofday_init(void)
{
	register_testsuite(&gettimeofday_ts);
}
