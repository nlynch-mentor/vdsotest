#include <assert.h>
#include <errno.h>
#include <error.h>
#include <sched.h>
#include <search.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "util.h"
#include "vdsotest.h"

static struct hsearch_data test_suite_htab;

void register_testsuite(const struct test_suite *ts)
{
	static bool initialized;
	ENTRY entry;
	ENTRY *res;

	if (!initialized) {
		if (hcreate_r(32, &test_suite_htab))
			error(EXIT_FAILURE, errno, "hcreate_r");
		initialized = true;
	}

	entry = (ENTRY) {
		.key = (void *)ts->name,
		.data = (void *)ts,
	};

	hsearch_r(entry, FIND, &res, &test_suite_htab);
	assert(res == NULL);
	if (!hsearch_r(entry, ENTER, &res, &test_suite_htab))
		error(EXIT_FAILURE, errno, "hsearch_r");
}

static void ctx_init_defaults(struct ctx *ctx)
{
	*ctx = (struct ctx) {
		.expired = 0,
		.duration = (struct itimerspec) {
			.it_value = (struct timespec) {
				.tv_sec = 1,
			},
		},
	};

	if (sched_getaffinity(getpid(), sizeof(ctx->cpus_allowed),
			      &ctx->cpus_allowed)) {
		error(EXIT_FAILURE, errno, "sched_getaffinity");
	}

	assert(CPU_COUNT(&ctx->cpus_allowed) > 0);
}

static void expiration_handler(int sig, siginfo_t *si, void *uc)
{
	struct ctx *ctx = si->si_value.sival_ptr;
	ctx->expired = 1;
}

static void ctx_start_timer(struct ctx *ctx)
{
	struct sigaction sa;
	struct sigevent sev;
	timer_t timer;

	ctx->expired = 0;

	sa = (struct sigaction) {
		.sa_flags = SA_SIGINFO,
		.sa_sigaction = expiration_handler,
	};

	if (sigaction(SIGRTMAX, &sa, NULL))
		error(EXIT_FAILURE, errno, "sigaction");

	sev = (struct sigevent) {
		.sigev_notify = SIGEV_SIGNAL,
		.sigev_signo = SIGRTMAX,
		.sigev_value.sival_ptr = ctx,
	};

	if (timer_create(CLOCK_MONOTONIC, &sev, &timer))
		error(EXIT_FAILURE, errno, "timer_create");

	if (timer_settime(timer, 0, &ctx->duration, NULL))
		error(EXIT_FAILURE, errno, "timer_settime");
}

static bool ctx_timer_expired(const struct ctx *ctx)
{
	return ctx->expired;
}

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

static const struct test_suite *test_suites[] = {
	&getcpu_ts,
};

static const struct test_suite *lookup_ts(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(test_suites); i++) {
		if (strcmp(name, test_suites[i]->name))
			continue;
		return test_suites[i];
	}

	return NULL;
}

static void usage(int ret)
{
	printf("Usage:\n\tNot recommended.\n");
	exit(ret);
}

int main(int argc, char **argv)
{
	struct bench_results bench_res;
	const struct test_suite *ts;
	const char *testname;
	const char *funcname;
	struct ctx ctx;
	int ret;

	srandom(getpid());

	ctx_init_defaults(&ctx);

	if (argc != 3)
		usage(EXIT_FAILURE);

	testname = argv[1];

	ts = lookup_ts(testname);
	if (!ts) {
		error(EXIT_FAILURE, 0, "Unknown test suite '%s' specified",
		      ts->name);
	}

	funcname = argv[2];

	if (!strcmp(funcname, "bench"))
		ret = ts->bench(&ctx, &bench_res);
	else if (!strcmp(funcname, "verify"))
		ret = ts->verify(&ctx);
	else
		usage(EXIT_FAILURE);

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
