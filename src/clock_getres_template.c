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

static void sys_clock_getres_simple(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = syscall(SYS_clock_getres, CLOCK_ID, arg);
	record_syscall_result(res, err, errno);
}

static void sys_clock_getres_prot(void *arg, struct syscall_result *res)
{
	void *buf;
	int err;

	buf = alloc_page((int)(unsigned long)arg);
	syscall_prepare();
	err = syscall(SYS_clock_getres, CLOCK_ID, buf);
	record_syscall_result(res, err, errno);
	free_page(buf);
}

static void clock_getres_simple(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = clock_getres(CLOCK_ID, arg);
	record_syscall_result(res, err, errno);
}

static void clock_getres_prot(void *arg, struct syscall_result *res)
{
	void *buf;
	int err;

	buf = alloc_page((int)(unsigned long)arg);
	syscall_prepare();
	err = clock_getres(CLOCK_ID, buf);
	record_syscall_result(res, err, errno);
	free_page(buf);
}

static void clock_getres_bogus_id(void *arg, struct syscall_result *res)
{
	struct timespec ts;
	int err;

	syscall_prepare();
	err = arg ? syscall(SYS_clock_getres, (clockid_t)-1, &ts) :
		clock_getres((clockid_t)-1, &ts);

	record_syscall_result(res, err, errno);
}

static void clock_getres_bogus_id_null(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = arg ? syscall(SYS_clock_getres, (clockid_t)-1, NULL) :
		clock_getres((clockid_t)-1, NULL);

	record_syscall_result(res, err, errno);
}

static const struct child_params clock_getres_abi_params[] = {
	/* Add tests for bogus clock id, null destination */

	/* Kernel sanity checks */

	{
		.desc = "passing NULL to sys_clock_getres",
		.func = sys_clock_getres_simple,
		.arg = NULL,
	},
	{
		.desc = "passing UINTPTR_MAX to sys_clock_getres",
		.func = sys_clock_getres_simple,
		.arg = (void *)ADDR_SPACE_END,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_NONE page to sys_clock_getres",
		.func = sys_clock_getres_prot,
		.arg = (void *)PROT_NONE,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_READ page to sys_clock_getres",
		.func = sys_clock_getres_prot,
		.arg = (void *)PROT_READ,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		/* This will be duplicated across the different clock
		 * id modules.  Oh well.
		 */
		.desc = "passing bogus clock id to SYS_clock_getres",
		.func = clock_getres_bogus_id,
		.arg = (void *)true, /* force syscall */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
	{
		/* This one too. */
		.desc = "passing bogus clock id and NULL to SYS_clock_getres",
		.func = clock_getres_bogus_id_null,
		.arg = (void *)true, /* force syscall */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},

	/* The below may be serviced by a vDSO, but not necessarily. */

	{
		.desc = "passing NULL to clock_getres",
		.func = clock_getres_simple,
		.arg = NULL,
	},
	{
		.desc = "passing UINTPTR_MAX to clock_getres",
		.func = clock_getres_simple,
		.arg = (void *)ADDR_SPACE_END,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_NONE page to clock_getres",
		.func = clock_getres_prot,
		.arg = (void *)PROT_NONE,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_READ page to clock_getres",
		.func = clock_getres_prot,
		.arg = (void *)PROT_READ,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		/* This will be duplicated across the different clock
		 * id modules.  Oh well.
		 */
		.desc = "passing bogus clock id to clock_getres",
		.func = clock_getres_bogus_id,
		.arg = (void *)false, /* use vdso */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
	{
		/* This one too. */
		.desc = "passing bogus clock id and NULL to clock_getres",
		.func = clock_getres_bogus_id_null,
		.arg = (void *)false, /* use vdso */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
};

static void clock_getres_abi(struct ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(clock_getres_abi_params); i++)
		run_as_child(ctx, &clock_getres_abi_params[i]);
}

static const struct test_suite clock_getres_ts = {
	.name = "clock-getres-" TS_SFX,
	.bench = clock_getres_bench,
	.verify = clock_getres_verify,
	.abi = clock_getres_abi,
};

static void __constructor clock_getres_init(void)
{
	register_testsuite(&clock_getres_ts);
}
