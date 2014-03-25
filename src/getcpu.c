#include <assert.h>
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

static void getcpu_syscall_nofail(unsigned *cpu, unsigned *node)
{
	int err;

	err = syscall(SYS_getcpu, cpu, node);
	if (err)
		error(EXIT_FAILURE, errno, "SYS_getcpu");
}


/* Set affinity to the current CPU */
static void getcpu_setup(const struct ctx *ctx)
{
	unsigned int cpu;
	cpu_set_t mask;

	getcpu_syscall_nofail(&cpu, NULL);

	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);

	if (sched_setaffinity(getpid(), sizeof(mask), &mask))
		error(EXIT_FAILURE, errno, "sched_setaffinity");
}

static void migrate(const struct ctx *ctx, cpu_set_t *cpus_allowed)
{
	unsigned int cpu;

	if (sched_getaffinity(getpid(), sizeof(cpu_set_t), cpus_allowed))
		error(EXIT_FAILURE, errno, "sched_getaffinity");

	getcpu_syscall_nofail(&cpu, NULL);

	assert(CPU_ISSET(cpu, cpus_allowed));

	CPU_CLR(cpu, cpus_allowed);

	if (CPU_COUNT(cpus_allowed) == 0) {
		*cpus_allowed = ctx->cpus_allowed;
	}

	if (sched_setaffinity(getpid(), sizeof(cpu_set_t), cpus_allowed))
		error(EXIT_FAILURE, errno, "sched_setaffinity");
}

static int getcpu_bench(struct ctx *ctx, struct bench_results *res)
{
	uint64_t vdsocalls;
	uint64_t syscalls;

	getcpu_setup(ctx);

	ctx_start_timer(ctx);

	for (vdsocalls = 0; !ctx_timer_expired(ctx); vdsocalls++) {
		sched_getcpu();
	}

	ctx_start_timer(ctx);

	for (syscalls = 0; !ctx_timer_expired(ctx); syscalls++) {
		syscall(SYS_getcpu, NULL, NULL);
	}

	printf("%s: syscalls = %llu, vdso calls = %llu\n", __func__,
	       (unsigned long long)syscalls, (unsigned long long)vdsocalls);

	return 0;
}

static int getcpu_verify(struct ctx *ctx)
{
	getcpu_setup(ctx);

	ctx_start_timer(ctx);

	while (!ctx_timer_expired(ctx)) {
		cpu_set_t cpus_allowed;
		unsigned long loops;
		unsigned long i;

		migrate(ctx, &cpus_allowed);
		loops = random() % 1000000;

		printf("loops = %ld\n", loops);

		for (i = 0; i < loops && !ctx_timer_expired(ctx); i++) {
			unsigned int cpu;

			cpu = sched_getcpu();

			if (!CPU_ISSET(cpu, &cpus_allowed)) {
				error(EXIT_FAILURE, 0, "sched_getcpu returned "
				      "unallowed cpu %d\n", cpu);
			}

			getcpu_syscall_nofail(&cpu, NULL);

			if (!CPU_ISSET(cpu, &cpus_allowed)) {
				error(EXIT_FAILURE, 0, "SYS_getcpu returned "
				      "unallowed cpu %d\n", cpu);
			}
		}
	}

	return 0;
}

static const struct test_suite getcpu_ts = {
	.name = "getcpu",
	.bench = getcpu_bench,
	.verify = getcpu_verify,
};

static void __constructor getcpu_init(void)
{
	register_testsuite(&getcpu_ts);
}
