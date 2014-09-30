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

static int (*clock_gettime_vdso)(clockid_t id, struct timespec *ts);

static bool vdso_has_clock_gettime(void)
{
	return clock_gettime_vdso != NULL;
}

static int clock_gettime_syscall_wrapper(clockid_t id, struct timespec *ts)
{
	return syscall(SYS_clock_gettime, id, ts);
}

static void clock_gettime_syscall_nofail(clockid_t id, struct timespec *ts)
{
	int err;

	err = clock_gettime_syscall_wrapper(id, ts);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_clock_gettime");
}

static void clock_gettime_vdso_nofail(clockid_t id, struct timespec *ts)
{
	int err;

	err = clock_gettime_vdso(id, ts);
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

	clock_gettime_syscall_nofail(CLOCK_ID, &now);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		struct timespec prev;

		if (!vdso_has_clock_gettime())
			goto skip_vdso;

		prev = now;

		clock_gettime_vdso_nofail(CLOCK_ID, &now);

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

	skip_vdso:
		prev = now;

		clock_gettime_syscall_nofail(CLOCK_ID, &now);

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

	ctx_cleanup_timer(ctx);
}

static void clock_gettime_bench(struct ctx *ctx, struct bench_results *res)
{
	struct timespec ts;

	if (vdso_has_clock_gettime()) {
		BENCH(ctx, clock_gettime_vdso(CLOCK_ID, &ts),
		      &res->vdso_interval);
	}

	BENCH(ctx, clock_gettime(CLOCK_ID, &ts),
	      &res->libc_interval);

	BENCH(ctx, clock_gettime_syscall_wrapper(CLOCK_ID, &ts),
	      &res->sys_interval);
}

static void sys_clock_gettime_simple(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = clock_gettime_syscall_wrapper(CLOCK_ID, arg);
	record_syscall_result(res, err, errno);
}

static void sys_clock_gettime_prot(void *arg, struct syscall_result *res)
{
	void *buf;
	int err;

	buf = alloc_page((int)(unsigned long)arg);
	syscall_prepare();
	err = clock_gettime_syscall_wrapper(CLOCK_ID, buf);
	record_syscall_result(res, err, errno);
	free_page(buf);
}

static void vdso_clock_gettime_simple(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = clock_gettime_vdso(CLOCK_ID, arg);
	record_syscall_result(res, err, errno);
}

static void vdso_clock_gettime_prot(void *arg, struct syscall_result *res)
{
	void *buf;
	int err;

	buf = alloc_page((int)(unsigned long)arg);
	syscall_prepare();
	err = clock_gettime_vdso(CLOCK_ID, buf);
	record_syscall_result(res, err, errno);
	free_page(buf);
}

static void clock_gettime_bogus_id(void *arg, struct syscall_result *res)
{
	struct timespec ts;
	int err;

	syscall_prepare();
	err = arg ? clock_gettime_syscall_wrapper((clockid_t)-1, &ts) :
		clock_gettime_vdso((clockid_t)-1, &ts);

	record_syscall_result(res, err, errno);
}

static void clock_gettime_bogus_id_null(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = arg ? clock_gettime_syscall_wrapper((clockid_t)-1, NULL) :
		clock_gettime_vdso((clockid_t)-1, NULL);

	record_syscall_result(res, err, errno);
}

static const struct child_params sys_clock_gettime_abi_params[] = {

	/* Kernel sanity checks */

	{
		.desc = "passing NULL to SYS_clock_gettime",
		.func = sys_clock_gettime_simple,
		.arg = NULL,
		.expected_ret = -1,
		.expected_errno = EFAULT,
	},
	{
		.desc = "passing UINTPTR_MAX to SYS_clock_gettime",
		.func = sys_clock_gettime_simple,
		.arg = (void *)ADDR_SPACE_END,
		.expected_ret = -1,
		.expected_errno = EFAULT,
	},
	{
		.desc = "passing PROT_NONE page to SYS_clock_gettime",
		.func = sys_clock_gettime_prot,
		.arg = (void *)PROT_NONE,
		.expected_ret = -1,
		.expected_errno = EFAULT,
	},
	{
		.desc = "passing PROT_READ page to SYS_clock_gettime",
		.func = sys_clock_gettime_prot,
		.arg = (void *)PROT_READ,
		.expected_ret = -1,
		.expected_errno = EFAULT,
	},
	{
		/* This will be duplicated across the different clock
		 * id modules.  Oh well.
		 */
		.desc = "passing bogus clock id to SYS_clock_gettime",
		.func = clock_gettime_bogus_id,
		.arg = (void *)true, /* force syscall */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
	{
		/* This one too. */
		.desc = "passing bogus clock id and NULL to SYS_clock_gettime",
		.func = clock_gettime_bogus_id_null,
		.arg = (void *)true, /* force syscall */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
};

static const struct child_params vdso_clock_gettime_abi_params[] = {
	/* The below will be serviced by a vDSO, if present. */

	{
		.desc = "passing NULL to clock_gettime",
		.func = vdso_clock_gettime_simple,
		.arg = NULL,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing UINTPTR_MAX to clock_gettime",
		.func = vdso_clock_gettime_simple,
		.arg = (void *)ADDR_SPACE_END,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_NONE page to clock_gettime",
		.func = vdso_clock_gettime_prot,
		.arg = (void *)PROT_NONE,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_READ page to clock_gettime",
		.func = vdso_clock_gettime_prot,
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
		.desc = "passing bogus clock id to clock_gettime",
		.func = clock_gettime_bogus_id,
		.arg = (void *)false, /* use vdso */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
	{
		/* This one too. */
		.desc = "passing bogus clock id and NULL to clock_gettime",
		.func = clock_gettime_bogus_id_null,
		.arg = (void *)false, /* use vdso */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
};

static void clock_gettime_abi(struct ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sys_clock_gettime_abi_params); i++)
		run_as_child(ctx, &sys_clock_gettime_abi_params[i]);

	if (vdso_has_clock_gettime()) {
		for (i = 0; i < ARRAY_SIZE(vdso_clock_gettime_abi_params); i++)
			run_as_child(ctx, &vdso_clock_gettime_abi_params[i]);
	}
}

static void clock_gettime_notes(struct ctx *ctx)
{
	if (!vdso_has_clock_gettime())
		printf("Note: vDSO version of clock_gettime not found\n");
}

static const char *clock_gettime_vdso_names[] = {
	"__kernel_clock_gettime",
	"__vdso_clock_gettime",
	NULL,
};

static void clock_gettime_bind(void *sym)
{
	clock_gettime_vdso = sym;
}

static const struct test_suite clock_gettime_ts = {
	.name = "clock-gettime-" TS_SFX,
	.bench = clock_gettime_bench,
	.verify = clock_gettime_verify,
	.abi = clock_gettime_abi,
	.notes = clock_gettime_notes,
	.vdso_names = clock_gettime_vdso_names,
	.bind = clock_gettime_bind,
};

static void __constructor clock_gettime_init(void)
{
	register_testsuite(&clock_gettime_ts);
}
