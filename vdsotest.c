#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

struct bench_results {
	int dummy;
};

struct ctx {
	volatile sig_atomic_t expired;
	struct itimerspec duration;
};

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

struct test_suite {
	const char *name; /* name of the API under test */

	/* Estimate speedup obtained by using vDSO implementation vs syscall */
	int (*bench)(struct ctx *ctx, struct bench_results *res);

	/* Check for inconsistencies between vDSO and syscall
	 * implemenations, usually by rapidly switching between the
	 * two modes and comparing results obtained.
	 */
	int (*verify)(struct ctx *ctx);

	/* Check for ABI inconsistencies, within reason - e.g. vDSO
	 * may get SIGSEGV where syscall may return EFAULT.
	 */
	int (*abi)(struct ctx *ctx);
};

static int getcpu_bench(struct ctx *ctx, struct bench_results *res)
{
	ctx_start_timer(ctx);

	while (!ctx_timer_expired(ctx)) {

	}

	return 0;
}

static int getcpu_verify(struct ctx *ctx)
{
	ctx_start_timer(ctx);

	while (!ctx_timer_expired(ctx)) {

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
