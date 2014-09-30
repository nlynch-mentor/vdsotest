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

static int (*clock_getres_vdso)(clockid_t id, struct timespec *ts);

static bool vdso_has_clock_getres(void)
{
	return clock_getres_vdso != NULL;
}

static int clock_getres_syscall_wrapper(clockid_t id, struct timespec *ts)
{
	return syscall(SYS_clock_getres, id, ts);
}

static void clock_getres_syscall_nofail(clockid_t id, struct timespec *ts)
{
	int err;

	err = clock_getres_syscall_wrapper(id, ts);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_clock_getres");
}

static void clock_getres_vdso_nofail(clockid_t id, struct timespec *ts)
{
	int err;

	err = clock_getres_vdso(id, ts);
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

/* Assume that reported resolution is constant */
static void clock_getres_verify(struct ctx *ctx)
{
	struct timespec sanity;

	clock_getres_syscall_nofail(CLOCK_ID, &sanity);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		struct timespec kres;
		struct timespec vres;

		clock_getres_syscall_nofail(CLOCK_ID, &kres);

		/* Check assumptions */
		if (!timespecs_equal(&kres, &sanity)) {
			error(EXIT_FAILURE, 0,
			      "clock resolution reported by kernel changed: "
			      "from [%ld, %ld] to [%ld, %ld]",
			      sanity.tv_sec, sanity.tv_nsec,
			      kres.tv_sec, kres.tv_nsec);
		}

		if (!vdso_has_clock_getres())
			continue;

		clock_getres_vdso_nofail(CLOCK_ID, &vres);
		if (!timespecs_equal(&kres, &vres)) {
			log_failure(ctx, "clock resolutions differ:\n"
				    "\t[%ld, %ld] (kernel)\n"
				    "\t[%ld, %ld] (vDSO)\n",
				    kres.tv_sec, kres.tv_nsec,
				    vres.tv_sec, vres.tv_nsec);
		}
	}

	ctx_cleanup_timer(ctx);
}

static void clock_getres_bench(struct ctx *ctx, struct bench_results *res)
{
	struct timespec ts;

	if (vdso_has_clock_getres()) {
		BENCH(ctx, clock_getres_vdso(CLOCK_ID, &ts),
		      &res->vdso_interval);
	}

	BENCH(ctx, clock_getres(CLOCK_ID, &ts),
	      &res->libc_interval);

	BENCH(ctx, clock_getres_syscall_wrapper(CLOCK_ID, &ts),
	      &res->sys_interval);
}

static void sys_clock_getres_simple(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = clock_getres_syscall_wrapper(CLOCK_ID, arg);
	record_syscall_result(res, err, errno);
}

static void sys_clock_getres_prot(void *arg, struct syscall_result *res)
{
	void *buf;
	int err;

	buf = alloc_page((int)(unsigned long)arg);
	syscall_prepare();
	err = clock_getres_syscall_wrapper(CLOCK_ID, buf);
	record_syscall_result(res, err, errno);
	free_page(buf);
}

static void vdso_clock_getres_simple(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = clock_getres_vdso(CLOCK_ID, arg);
	record_syscall_result(res, err, errno);
}

static void vdso_clock_getres_prot(void *arg, struct syscall_result *res)
{
	void *buf;
	int err;

	buf = alloc_page((int)(unsigned long)arg);
	syscall_prepare();
	err = clock_getres_vdso(CLOCK_ID, buf);
	record_syscall_result(res, err, errno);
	free_page(buf);
}

static void clock_getres_bogus_id(void *arg, struct syscall_result *res)
{
	struct timespec ts;
	int err;

	syscall_prepare();
	err = arg ? clock_getres_syscall_wrapper((clockid_t)-1, &ts) :
		clock_getres_vdso((clockid_t)-1, &ts);

	record_syscall_result(res, err, errno);
}

static void clock_getres_bogus_id_null(void *arg, struct syscall_result *res)
{
	int err;

	syscall_prepare();
	err = arg ? clock_getres_syscall_wrapper((clockid_t)-1, NULL) :
		clock_getres_vdso((clockid_t)-1, NULL);

	record_syscall_result(res, err, errno);
}

static const struct child_params sys_clock_getres_abi_params[] = {
	/* Kernel sanity checks */

	{
		.desc = "passing NULL to clock_getres (syscall)",
		.func = sys_clock_getres_simple,
		.arg = NULL,
	},
	{
		.desc = "passing UINTPTR_MAX to clock_getres (syscall)",
		.func = sys_clock_getres_simple,
		.arg = (void *)ADDR_SPACE_END,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_NONE page to clock_getres (syscall)",
		.func = sys_clock_getres_prot,
		.arg = (void *)PROT_NONE,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_READ page to clock_getres (syscall)",
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
		.desc = "passing bogus clock id to clock_getres (syscall)",
		.func = clock_getres_bogus_id,
		.arg = (void *)true, /* force syscall */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
	{
		/* This one too. */
		.desc = "passing bogus clock id and NULL to clock_getres (syscall)",
		.func = clock_getres_bogus_id_null,
		.arg = (void *)true, /* force syscall */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
};

static const struct child_params vdso_clock_getres_abi_params[] = {
	/* The below will be serviced by a vDSO, if present. */

	{
		.desc = "passing NULL to clock_getres (VDSO)",
		.func = vdso_clock_getres_simple,
		.arg = NULL,
	},
	{
		.desc = "passing UINTPTR_MAX to clock_getres (VDSO)",
		.func = vdso_clock_getres_simple,
		.arg = (void *)ADDR_SPACE_END,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_NONE page to clock_getres (VDSO)",
		.func = vdso_clock_getres_prot,
		.arg = (void *)PROT_NONE,
		.expected_ret = -1,
		.expected_errno = EFAULT,
		.signal_set = {
			.mask = SIGNO_TO_BIT(SIGSEGV),
		},
	},
	{
		.desc = "passing PROT_READ page to clock_getres (VDSO)",
		.func = vdso_clock_getres_prot,
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
		.desc = "passing bogus clock id to clock_getres (VDSO)",
		.func = clock_getres_bogus_id,
		.arg = (void *)false, /* use vdso */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
	{
		/* This one too. */
		.desc = "passing bogus clock id and NULL to clock_getres (VDSO)",
		.func = clock_getres_bogus_id_null,
		.arg = (void *)false, /* use vdso */
		.expected_ret = -1,
		.expected_errno = EINVAL,
	},
};

static void clock_getres_abi(struct ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sys_clock_getres_abi_params); i++)
		run_as_child(ctx, &sys_clock_getres_abi_params[i]);

	if (vdso_has_clock_getres()) {
		for (i = 0; i < ARRAY_SIZE(vdso_clock_getres_abi_params); i++)
			run_as_child(ctx, &vdso_clock_getres_abi_params[i]);
	}
}

static void clock_getres_notes(struct ctx *ctx)
{
	if (!vdso_has_clock_getres())
		printf("Note: vDSO version of clock_getres not found\n");
}

static const char *clock_getres_vdso_names[] = {
	"__kernel_clock_getres",
	"__vdso_clock_getres",
	NULL,
};

static void clock_getres_bind(void *sym)
{
	clock_getres_vdso = sym;
}

static const struct test_suite clock_getres_ts = {
	.name = "clock-getres-" TS_SFX,
	.bench = clock_getres_bench,
	.verify = clock_getres_verify,
	.abi = clock_getres_abi,
	.notes = clock_getres_notes,
	.vdso_names = clock_getres_vdso_names,
	.bind = clock_getres_bind,
};

static void __constructor clock_getres_init(void)
{
	register_testsuite(&clock_getres_ts);
}
