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

#define NSEC_PER_SEC 1000000000

static void clock_gettime_syscall_nofail(struct timespec *ts)
{
	int err;

	err = syscall(SYS_clock_gettime, CLOCK_ID, ts);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_clock_gettime");
}

static void clock_gettime_libc_nofail(struct timespec *ts)
{
	int err;

	err = clock_gettime(CLOCK_ID, ts);
	if (err)
		error(EXIT_FAILURE, errno, "clock_gettime");
}

static bool timespecs_ordered(const struct timespec *first,
			      const struct timespec *second)
{
	if (first->tv_sec < second->tv_sec)
		return true;

	if (first->tv_sec == second->tv_sec)
		return first->tv_nsec <= second->tv_nsec;

	return false;
}

static bool timespec_normalized(const struct timespec *ts)
{
	if (ts->tv_sec < 0)
		return false;
	if (ts->tv_nsec < 0)
		return false;
	if (ts->tv_nsec >= NSEC_PER_SEC)
		return false;
	return true;
}

static void clock_gettime_verify(struct ctx *ctx)
{
	struct timespec now;

	clock_gettime_syscall_nofail(&now);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		struct timespec prev;

		prev = now;

		clock_gettime_libc_nofail(&now);

		if (!timespec_normalized(&now)) {
			log_failure(ctx, "timestamp obtained from libc/vDSO "
				    "not normalized:\n"
				    "\t[%ld, %ld]\n",
				    now.tv_sec, now.tv_nsec);
		}

		if (!timespecs_ordered(&prev, &now)) {
			log_failure(ctx, "timestamp obtained from libc/vDSO "
				    "predates timestamp\n"
				    "previously obtained from kernel:\n"
				    "\t[%ld, %ld] (kernel)\n"
				    "\t[%ld, %ld] (vDSO)\n",
				    prev.tv_sec, prev.tv_nsec,
				    now.tv_sec, now.tv_nsec);
		}

		prev = now;

		clock_gettime_syscall_nofail(&now);

		if (!timespec_normalized(&now)) {
			log_failure(ctx, "timestamp obtained from kernel "
				    "not normalized:\n"
				    "\t[%ld, %ld]\n",
				    now.tv_sec, now.tv_nsec);
		}

		if (!timespecs_ordered(&prev, &now)) {
			log_failure(ctx, "timestamp obtained from kernel "
				    "predates timestamp\n"
				    "previously obtained from libc/vDSO:\n"
				    "\t[%ld, %ld] (vDSO)\n"
				    "\t[%ld, %ld] (kernel)\n",
				    prev.tv_sec, prev.tv_nsec,
				    now.tv_sec, now.tv_nsec);
		}

	}
}

static void clock_gettime_bench(struct ctx *ctx, struct bench_results *res)
{
	struct timespec ts;
	uint64_t calls;

	ctx_start_timer(ctx);

	bench_interval_begin(&res->vdso_interval, calls);

	while (!test_should_stop(ctx)) {
		clock_gettime(CLOCK_ID, &ts);
		calls++;
	}

	bench_interval_end(&res->vdso_interval, calls);

	ctx_start_timer(ctx);

	bench_interval_begin(&res->sys_interval, calls);

	while (!test_should_stop(ctx)) {
		syscall(SYS_clock_gettime, CLOCK_ID, &ts);
		calls++;
	}

	bench_interval_end(&res->sys_interval, calls);
}


static const struct test_suite clock_gettime_ts = {
	.name = TS_NAME,
	.bench = clock_gettime_bench,
	.verify = clock_gettime_verify,
};

static void __constructor clock_gettime_init(void)
{
	register_testsuite(&clock_gettime_ts);
}
