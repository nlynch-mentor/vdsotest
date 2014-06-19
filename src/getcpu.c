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
#include <dlfcn.h>
#include <errno.h>
#include <error.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "compiler.h"
#include "vdsotest.h"

static int getcpu_syscall_wrapper(unsigned *cpu, unsigned *node, void *tcache)
{
	return syscall(SYS_getcpu, cpu, node, tcache);
}

static int (*getcpu)(unsigned *cpu, unsigned *node, void *tcache) =
	getcpu_syscall_wrapper;

static void getcpu_syscall_nofail(unsigned *cpu, unsigned *node, void *tcache)
{
	int err;

	err = getcpu_syscall_wrapper(cpu, node, tcache);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_getcpu");
}

static void getcpu_nofail(unsigned *cpu, unsigned *node, void *tcache)
{
	int err;

	err = getcpu(cpu, node, tcache);
	if (err)
		error(EXIT_FAILURE, errno, "getcpu");
}

/* Force the scheduler to migrate us off the current cpu.  Return new
 * affinity mask in cpus_allowed.
 */
static void force_migrate(const struct ctx *ctx, cpu_set_t *cpus_allowed)
{
	unsigned int cpu;

	if (sched_getaffinity(getpid(), sizeof(cpu_set_t), cpus_allowed))
		error(EXIT_FAILURE, errno, "sched_getaffinity");

	getcpu_syscall_nofail(&cpu, NULL, NULL);

	assert(CPU_ISSET(cpu, cpus_allowed));

	CPU_CLR(cpu, cpus_allowed);

	if (CPU_COUNT(cpus_allowed) == 0) {
		*cpus_allowed = ctx->cpus_allowed;
		debug(ctx, "resetting cpus_allowed to original\n");
	} else {
		debug(ctx, "migrating off cpu %d\n", cpu);
	}

	if (sched_setaffinity(getpid(), sizeof(cpu_set_t), cpus_allowed))
		error(EXIT_FAILURE, errno, "sched_setaffinity");
}

static void getcpu_bench(struct ctx *ctx, struct bench_results *res)
{
	uint64_t calls;
	unsigned int cpu;

	ctx_start_timer(ctx);

	bench_interval_begin(&res->vdso_interval, calls);

	while (!test_should_stop(ctx)) {
		getcpu(&cpu, NULL, NULL);
		calls++;
	}

	bench_interval_end(&res->vdso_interval, calls);

	ctx_cleanup_timer(ctx);

	ctx_start_timer(ctx);

	bench_interval_begin(&res->sys_interval, calls);

	while (!test_should_stop(ctx)) {
		getcpu_syscall_wrapper(&cpu, NULL, NULL);
		calls++;
	}

	bench_interval_end(&res->sys_interval, calls);

	ctx_cleanup_timer(ctx);
}

static void subtimer_set_duration(const struct ctx *ctx, struct timespec *ts)
{
	uint64_t subtimer_ns;
	uint64_t total_ns;

	total_ns = timespec_to_nsec(&ctx->duration.it_value);

	assert(CPU_COUNT(&ctx->cpus_allowed) > 0);

	/* For N CPUs, we want to migrate N^2 times */
	subtimer_ns = total_ns / CPU_COUNT(&ctx->cpus_allowed);
	subtimer_ns /= CPU_COUNT(&ctx->cpus_allowed);

	debug(ctx, "subtimer_ns = %lld\n", (unsigned long long)subtimer_ns);

	*ts = nsec_to_timespec(subtimer_ns);
}

static void expiration_handler(int sig, siginfo_t *si, void *uc)
{
	volatile sig_atomic_t *expired = si->si_value.sival_ptr;

	*expired = 1;
}

static timer_t subtimer_start(const struct timespec *duration,
			      volatile sig_atomic_t *flag)
{
	struct itimerspec its;
	struct sigaction sa;
	struct sigevent sev;
	timer_t timer;

	sa = (struct sigaction) {
		.sa_flags = SA_SIGINFO,
		.sa_sigaction = expiration_handler,
	};

	if (sigaction(SUBTIMER_SIGNO, &sa, NULL))
		error(EXIT_FAILURE, errno, "sigaction");

	sev = (struct sigevent) {
		.sigev_notify = SIGEV_SIGNAL,
		.sigev_signo = SUBTIMER_SIGNO,
		.sigev_value.sival_ptr = (void *)flag,
	};

	if (timer_create(CLOCK_MONOTONIC, &sev, &timer))
		error(EXIT_FAILURE, errno, "timer_create");

	its = (struct itimerspec) {
		.it_value = *duration,
	};

	if (timer_settime(timer, 0, &its, NULL))
		error(EXIT_FAILURE, errno, "timer_settime");

	return timer;
}

static void subtimer_cleanup(timer_t timer)
{
	if (timer_delete(timer)) {
		error(EXIT_FAILURE, errno, "timer_delete");
	}
}

static void getcpu_verify(struct ctx *ctx)
{
	cpu_set_t cpus_allowed = ctx->cpus_allowed;
	struct timespec subtimer_duration;

	subtimer_set_duration(ctx, &subtimer_duration);

	ctx_start_timer(ctx);

	while (!test_should_stop(ctx)) {
		volatile sig_atomic_t expired;
		timer_t subtimer;

		expired = 0;

		subtimer = subtimer_start(&subtimer_duration, &expired);

		while (!expired && !test_should_stop(ctx)) {
			unsigned int cpu;

			getcpu_syscall_nofail(&cpu, NULL, NULL);

			if (!CPU_ISSET(cpu, &cpus_allowed)) {
				log_failure(ctx, "SYS_getcpu returned "
					    "unallowed cpu %d\n", cpu);
			}
			getcpu_nofail(&cpu, NULL, NULL);

			if (!CPU_ISSET(cpu, &cpus_allowed)) {
				log_failure(ctx, "sched_getcpu returned "
					    "unallowed cpu %d\n", cpu);
			}

		}

		subtimer_cleanup(subtimer);

		force_migrate(ctx, &cpus_allowed);
	}

	ctx_cleanup_timer(ctx);
}

struct getcpu_args {
	unsigned int *cpu;
	unsigned int *node;
	void *tcache;
	bool force_syscall;
};

enum getcpu_arg_type {
	valid,
	nullptr,
	bogus,
	prot_none,
	prot_read,
	getcpu_arg_type_max,
};

static const char *getcpu_arg_type_str[] = {
	[valid] = "valid",
	[nullptr] = "NULL",
	[bogus] = "UINTPTR_MAX",
	[prot_none] = "page (PROT_NONE)",
	[prot_read] = "page (PROT_READ)",
};

static void do_getcpu(void *arg, struct syscall_result *res)
{
	struct getcpu_args *args = arg;
	int err;

	syscall_prepare();
	if (args->force_syscall) {
		err = getcpu_syscall_wrapper(args->cpu, args->node,
					     args->tcache);
	} else {
		err = getcpu(args->cpu, args->node, args->tcache);
	}

	record_syscall_result(res, err, errno);
}

static void *getcpu_arg_alloc(enum getcpu_arg_type t)
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

static void getcpu_arg_release(void *buf, enum getcpu_arg_type t)
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

static bool __pure getcpu_args_should_fault(enum getcpu_arg_type tv,
					    enum getcpu_arg_type tz,
					    enum getcpu_arg_type tcache)
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

	switch (tcache) {
	case valid:
	case nullptr:
	case bogus:
	case prot_none:
	case prot_read:
		/* tcache should be ignored completely */
		break;
	default:
		assert(false);
		break;
	}

	return false;
}

static void getcpu_abi_cpu_node(struct ctx *ctx,
				unsigned int *cpu,
				enum getcpu_arg_type cpu_type,
				unsigned int *node,
				enum getcpu_arg_type node_type)
{
	enum getcpu_arg_type tc_type;

	for (tc_type = 0; tc_type < getcpu_arg_type_max; tc_type++) {
		struct signal_set signal_set;
		struct child_params parms;
		struct getcpu_args args;
		int expected_errno;
		int expected_ret;
		char *desc;
		void *tc;

		tc = getcpu_arg_alloc(tc_type);

		/* First, force system call */
		args = (struct getcpu_args) {
			.cpu = cpu,
			.node = node,
			.tcache = tc,
			.force_syscall = true,
		};

		expected_ret = 0;
		if (getcpu_args_should_fault(cpu_type, node_type, tc_type))
			expected_ret = -1;

		expected_errno = 0;
		if (getcpu_args_should_fault(cpu_type, node_type, tc_type))
			expected_errno = EFAULT;

		/* Should never actually terminate by signal
		 * for syscall.
		 */
		signal_set.mask = 0;

		xasprintf(&desc, "SYS_getcpu(%s, %s, %s)",
			  getcpu_arg_type_str[cpu_type],
			  getcpu_arg_type_str[node_type],
			  getcpu_arg_type_str[tc_type]);

		parms = (struct child_params) {
			.desc = desc,
			.func = do_getcpu,
			.arg = &args,
			.expected_ret = expected_ret,
			.expected_errno = expected_errno,
			.signal_set = signal_set,
		};

		run_as_child(ctx, &parms);

		xfree(desc);

		/* Now do libc/vDSO */

		args.force_syscall = false;

		if (getcpu_args_should_fault(cpu_type, node_type, tc_type))
			signal_set.mask |= SIGNO_TO_BIT(SIGSEGV);

		xasprintf(&desc, "getcpu(%s, %s, %s)",
			  getcpu_arg_type_str[cpu_type],
			  getcpu_arg_type_str[node_type],
			  getcpu_arg_type_str[tc_type]);

		parms.desc = desc;
		parms.signal_set = signal_set;

		run_as_child(ctx, &parms);

		xfree(desc);

		getcpu_arg_release(tc, tc_type);
	}
}

static void getcpu_abi_cpu(struct ctx *ctx,
			   unsigned int *cpu,
			   enum getcpu_arg_type cpu_type)
{
	enum getcpu_arg_type node_type;

	for (node_type = 0; node_type < getcpu_arg_type_max; node_type++) {
		unsigned int *node;

		node = getcpu_arg_alloc(node_type);

		getcpu_abi_cpu_node(ctx, cpu, cpu_type, node, node_type);

		getcpu_arg_release(node, node_type);
	}
}

static void getcpu_abi(struct ctx *ctx)
{
	enum getcpu_arg_type cpu_type;

	for (cpu_type = 0; cpu_type < getcpu_arg_type_max; cpu_type++) {
		unsigned int *cpu;

		cpu = getcpu_arg_alloc(cpu_type);

		getcpu_abi_cpu(ctx, cpu, cpu_type);

		getcpu_arg_release(cpu, cpu_type);
	}
}

static void getcpu_notes(struct ctx *ctx)
{
	if (getcpu == getcpu_syscall_wrapper)
		printf("Note: vDSO version of getcpu not found\n");
}

static const char *getcpu_vdso_names[] = {
	"__kernel_getcpu",
	"__vdso_getcpu",
	NULL,
};

static void getcpu_bind(void *sym)
{
	getcpu = sym;
}

static const struct test_suite getcpu_ts = {
	.name = "getcpu",
	.bench = getcpu_bench,
	.verify = getcpu_verify,
	.abi = getcpu_abi,
	.notes = getcpu_notes,
	.vdso_names = getcpu_vdso_names,
	.bind = getcpu_bind,
};

static void __constructor getcpu_init(void)
{
	register_testsuite(&getcpu_ts);
}
