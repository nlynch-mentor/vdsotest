#include <assert.h>
#include <errno.h>
#include <error.h>
#include <sched.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "compiler.h"
#include "util.h"
#include "vdsotest.h"

static void inc_fail_count(struct ctx *ctx)
{
	ctx->fails++;
	if (ctx->fails >= ctx->max_fails) {
		ctx->should_stop = 1;
		fprintf(stderr, "Failure threshold (%llu) reached; "
			"stopping test.\n", ctx->max_fails);
	}
}

void log_failure(struct ctx *ctx, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	inc_fail_count(ctx);
}

static struct hashtable test_suite_htab;

void register_testsuite(const struct test_suite *ts)
{
	hashtable_add(&test_suite_htab, ts->name, ts);
}

static const struct test_suite *lookup_ts(const char *name)
{
	return hashtable_lookup(&test_suite_htab, name);
}

static void ctx_init_defaults(struct ctx *ctx)
{
	*ctx = (struct ctx) {
		.duration = (struct itimerspec) {
			.it_value = (struct timespec) {
				.tv_sec = 1,
			},
		},
		.max_fails = 10,
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
	ctx->should_stop = 1;
}

void ctx_start_timer(struct ctx *ctx)
{
	struct sigaction sa;
	struct sigevent sev;
	timer_t timer;

	ctx->should_stop = 0;

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

enum testfunc_result {
	TF_OK,     /* Test completed without failure */
	TF_FAIL,   /* One or more failures/inconsistencies encountered */
	TF_NOIMPL, /* Function not implemented */
};

static enum testfunc_result
testsuite_run_bench(struct ctx *ctx, const struct test_suite *ts)
{
	if (!ts->bench)
		return TF_NOIMPL;

	ts->bench(ctx, NULL);

	return ctx->fails ? TF_FAIL : TF_OK;
}

static enum testfunc_result
testsuite_run_verify(struct ctx *ctx, const struct test_suite *ts)
{
	if (!ts->verify)
		return TF_NOIMPL;

	ts->verify(ctx);

	return ctx->fails ? TF_FAIL : TF_OK;
}

static enum testfunc_result
testsuite_run_abi(struct ctx *ctx, const struct test_suite *ts)
{
	if (!ts->abi)
		return TF_NOIMPL;

	ts->abi(ctx);

	return ctx->fails ? TF_FAIL : TF_OK;
}

typedef enum testfunc_result (*testfunc_t)(struct ctx *, const struct test_suite *);

static struct hashtable test_func_htab;

static void register_testfunc(const char *name, testfunc_t func)
{
	hashtable_add(&test_func_htab, name, func);
}

static testfunc_t lookup_tf(const char *name)
{
	return hashtable_lookup(&test_func_htab, name);
}

static void __constructor register_testfuncs(void)
{
	register_testfunc("verify", testsuite_run_verify);
	register_testfunc("bench",  testsuite_run_bench);
	register_testfunc("abi",    testsuite_run_abi);
}

int main(int argc, char **argv)
{
	const struct test_suite *ts;
	enum testfunc_result tf_ret;
	const char *testname;
	const char *funcname;
	struct ctx ctx;
	testfunc_t tf;
	int ret;

	ret = EXIT_SUCCESS;

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

	tf = lookup_tf(funcname);
	if (!tf) {
		error(EXIT_FAILURE, 0, "Unknown test function '%s' specified",
		      funcname);
	}

	tf_ret = tf(&ctx, ts);

	if (tf_ret == TF_NOIMPL) {
		printf("%s/%s: unimplemented\n", testname, funcname);
	} else if (ctx.fails > 0) {
		printf("%s/%s: %llu failures/inconsistencies encountered\n",
		       testname, funcname, ctx.fails);
		ret = EXIT_FAILURE;
	}

	return ret;
}
