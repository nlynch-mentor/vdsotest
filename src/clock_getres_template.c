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

static void clock_getres_syscall_nofail(struct timespec *ts)
{
	int err;

	err = syscall(SYS_clock_getres, CLOCK_ID, ts);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_clock_getres");
}

static void clock_getres_libc_nofail(struct timespec *ts)
{
	int err;

	err = clock_getres(CLOCK_ID, ts);
	if (err)
		error(EXIT_FAILURE, errno, "clock_getres");
}

static bool timespecs_equal(const struct timespec *first,
			    const struct timespec *second)
{
	if (first->tv_sec != second->tv_sec)
		return false;
	if (first->tv_nsec != second->tv_nsec)
		return false;
	return true;
}

/* Assume that reported resolution is constant, don't use timer */
static void clock_getres_verify(struct ctx *ctx)
{
	struct timespec sanity;

	clock_getres_syscall_nofail(&sanity);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		struct timespec kres;
		struct timespec vres;

		clock_getres_syscall_nofail(&kres);
		clock_getres_libc_nofail(&vres);

		/* Check assumptions */
		if (!timespecs_equal(&kres, &sanity)) {
			error(EXIT_FAILURE, 0,
			      "clock resolution reported by kernel changed: "
			      "from [%ld, %ld] to [%ld, %ld]",
			      sanity.tv_sec, sanity.tv_nsec,
			      kres.tv_sec, kres.tv_nsec);
		}

		if (timespecs_equal(&kres, &vres)) {
			debug(ctx, "clock resolutions match ([%ld, %ld])\n",
				kres.tv_sec, kres.tv_nsec);
		} else {
			log_failure(ctx, "clock resolutions differ:\n"
				    "\t[%ld, %ld] (kernel)\n"
				    "\t[%ld, %ld] (vDSO)\n",
				    kres.tv_sec, kres.tv_nsec,
				    vres.tv_sec, vres.tv_nsec);
		}
	}
}

static void clock_getres_bench(struct ctx *ctx, struct bench_results *res)
{
	struct timespec ts;
	uint64_t calls;

	ctx_start_timer(ctx);

	bench_interval_begin(&res->vdso_interval, calls);

	while (!test_should_stop(ctx)) {
		clock_getres(CLOCK_ID, &ts);
		calls++;
	}

	bench_interval_end(&res->vdso_interval, calls);

	ctx_start_timer(ctx);

	bench_interval_begin(&res->sys_interval, calls);

	while (!test_should_stop(ctx)) {
		syscall(SYS_clock_getres, CLOCK_ID, &ts);
		calls++;
	}

	bench_interval_end(&res->sys_interval, calls);
}


static const struct test_suite clock_getres_ts = {
	.name = "clock-getres-" TS_SFX,
	.bench = clock_getres_bench,
	.verify = clock_getres_verify,
};

static void __constructor clock_getres_init(void)
{
	register_testsuite(&clock_getres_ts);
}
