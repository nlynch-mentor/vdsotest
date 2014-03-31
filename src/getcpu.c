#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <error.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "compiler.h"
#include "vdsotest.h"

static int (*getcpu)(unsigned *cpu, unsigned *node, void *tcache);

static int getcpu_syscall_wrapper(unsigned *cpu, unsigned *node, void *tcache)
{
	return syscall(SYS_getcpu, cpu, node, tcache);
}

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

	ctx_start_timer(ctx);

	bench_interval_begin(&res->sys_interval, calls);

	while (!test_should_stop(ctx)) {
		getcpu_syscall_wrapper(&cpu, NULL, NULL);
		calls++;
	}

	bench_interval_end(&res->sys_interval, calls);
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
}

static void getcpu_notes(struct ctx *ctx)
{
	if (getcpu == getcpu_syscall_wrapper)
		printf("Note: vDSO version of getcpu not found\n");
}

static const struct test_suite getcpu_ts = {
	.name = "getcpu",
	.bench = getcpu_bench,
	.verify = getcpu_verify,
	.notes = getcpu_notes,
};

static const char *getcpu_vdso_names[] = {
	"__kernel_getcpu",
	"__vdso_getcpu",
};

static void __constructor getcpu_init(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(getcpu_vdso_names); i++) {
		getcpu = get_vdso_sym(getcpu_vdso_names[i]);
		if (getcpu)
			break;
	}

	if (!getcpu)
		getcpu = getcpu_syscall_wrapper;

	register_testsuite(&getcpu_ts);
}
