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
		if (!hcreate_r(32, &test_suite_htab))
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

static const struct test_suite *lookup_ts(const char *name)
{
	ENTRY entry;
	ENTRY *res;

	entry = (ENTRY) {
		.key = (void *)name,
	};

	hsearch_r(entry, FIND, &res, &test_suite_htab);

	return res ? res->data : NULL;
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

void ctx_start_timer(struct ctx *ctx)
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
		      testname);
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
