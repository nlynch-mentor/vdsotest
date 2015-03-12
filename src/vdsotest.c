/*
 * vdsotest - a utility for verifying and benchmarking a Linux VDSO
 *
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

#include <argp.h>
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "compiler.h"
#include "util.h"
#include "vdsotest.h"

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

static struct hashtable test_suite_htab;
static struct hashtable test_func_htab;

static char *api_list;
static char *test_type_list;

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

void verbose(const struct ctx *ctx, const char *fmt, ...)
{
	va_list args;

	if (!ctx->verbose && !ctx->debug)
		return;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void __debug(const struct ctx *ctx, const char *fn, int line,
	     const char *fmt, ...)
{
	va_list args;

	if (!ctx->debug)
		return;

	printf("%s:%d: ", fn, line);

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
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

	if (sigaction(TIMER_SIGNO, &sa, NULL))
		error(EXIT_FAILURE, errno, "sigaction");

	sev = (struct sigevent) {
		.sigev_notify = SIGEV_SIGNAL,
		.sigev_signo = TIMER_SIGNO,
		.sigev_value.sival_ptr = ctx,
	};

	if (timer_create(CLOCK_MONOTONIC, &sev, &timer))
		error(EXIT_FAILURE, errno, "timer_create");

	if (timer_settime(timer, 0, &ctx->duration, NULL))
		error(EXIT_FAILURE, errno, "timer_settime");

	ctx->timer = timer;
}

void ctx_cleanup_timer(struct ctx *ctx)
{
	timer_delete(ctx->timer);
}

void run_as_child(struct ctx *ctx, const struct child_params *parms)
{
	struct child_status {
		int wstatus; /* waitpid result */
		bool wsignaled;
		union {
			int wtermsig;    /* if wsignaled == true */
			int wexitstatus; /* otherwise */
		};
	} cstatus;
	pid_t pid;

	cstatus = (struct child_status) { };

	fflush(NULL);
	pid = fork();
	if (pid == 0) {
		struct syscall_result syscall_result;

		parms->func(parms->arg, &syscall_result);

		if (syscall_result.sr_ret != parms->expected_ret) {
			fprintf(stderr, "%s: unexpected return value %d, "
				"expected %d\n", parms->desc,
				syscall_result.sr_ret,
				parms->expected_ret);
			exit(EXIT_FAILURE);
		}

		if (syscall_result.sr_errno != parms->expected_errno) {
			fprintf(stderr, "%s: unexpected errno %d (%s), "
				"expected %d (%s)\n",
				parms->desc,
				syscall_result.sr_errno,
				strerror(syscall_result.sr_errno),
				parms->expected_errno,
				strerror(parms->expected_errno));
			exit(EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	while (waitpid(pid, &cstatus.wstatus, 0) != pid) {
		if (errno == EINTR)
			continue;
		error(EXIT_FAILURE, errno, "waitpid");
	}

	if (WIFEXITED(cstatus.wstatus)) {
		cstatus.wsignaled = false;
		cstatus.wexitstatus = WEXITSTATUS(cstatus.wstatus);
	} else if (WIFSIGNALED(cstatus.wstatus)) {
		cstatus.wsignaled = true;
		cstatus.wtermsig = WTERMSIG(cstatus.wstatus);
	} else {
		error(EXIT_FAILURE, 0, "unhandled wait status %d",
		      cstatus.wstatus);
	}

	if (!cstatus.wsignaled && cstatus.wexitstatus != EXIT_SUCCESS) {
		log_failure(ctx, "%s: exited with status %d, "
			    "expected %d\n", parms->desc,
			    cstatus.wexitstatus, EXIT_SUCCESS);
	} else if (cstatus.wsignaled &&
	    !signal_in_set(&parms->signal_set, cstatus.wtermsig)) {
		log_failure(ctx, "%s: terminated by unexpected signal %d\n",
			  parms->desc, cstatus.wtermsig);
	} else {
		verbose(ctx, "%-70s OK\n", parms->desc);
	}
}

enum testfunc_result {
	TF_OK,     /* Test completed without failure */
	TF_FAIL,   /* One or more failures/inconsistencies encountered */
	TF_NOIMPL, /* Function not implemented */
};

static void bench_report(const char *api, const char *impl,
			 const struct bench_interval *ival)
{
	if (ival->calls == 0) {
		printf("%s: %s not tested\n", api, impl);
		return;
	}

	printf("%s: %s calls per second: %llu (%llu nsec/call)\n",
	       api, impl,
	       (unsigned long long)ival->calls_per_sec,
	       (unsigned long long)ival->duration_nsec / ival->calls);
}

static enum testfunc_result
testsuite_run_bench(struct ctx *ctx, const struct test_suite *ts)
{
	struct bench_results bres;
	if (!ts->bench)
		return TF_NOIMPL;

	bres = (struct bench_results) { };

	ts->bench(ctx, &bres);

	if (ctx->fails)
		return TF_FAIL;

	verbose(ctx,
		"%s: syscalls = %llu, vdso calls = %llu, libc calls = %llu\n",
		ts->name,
		(unsigned long long)bres.sys_interval.calls,
		(unsigned long long)bres.vdso_interval.calls,
		(unsigned long long)bres.libc_interval.calls);

	bench_report(ts->name, "system", &bres.sys_interval);
	bench_report(ts->name, "  libc", &bres.libc_interval);
	bench_report(ts->name, "  vdso", &bres.vdso_interval);

	return TF_OK;
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

static void register_testfunc(const char *name, testfunc_t func)
{
	char *new_test_type_list;

	xasprintf(&new_test_type_list, "%s\t%s\n",
		  test_type_list ? test_type_list : "", name);
	xfree(test_type_list);
	test_type_list = new_test_type_list;
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

static const struct argp_option options[] = {
	{
		.name = "debug",
		.key = 'g',
		.doc = "Enable debug output which may perturb bench results; "
		       "implies --verbose",
	},
	{
		.name = "duration",
		.key = 'd',
		.doc = "Duration of test run in seconds (default 1)",
		.arg = "SEC",
	},
	{
		.name = "maxfails",
		.key = 'f',
		.doc = "Maximum number of failures before terminating "
		       "test run (default 10)",
		.arg = "NUM",
	},
	{
		.name = "verbose",
		.key = 'v',
		.doc = "Enable verbose output",
	},
	{ 0 },
};

static void list_apis(struct ctx *ctx)
{
	printf("%s", api_list);
	exit(EXIT_SUCCESS);
}

static void list_test_types(struct ctx *ctx)
{
	printf("%s", test_type_list);
	exit(EXIT_SUCCESS);
}

static error_t parse(int key, char *arg, struct argp_state *state)
{
	struct ctx *ctx;

	ctx = state->input;

	switch (key) {
	case 'd':
		ctx->duration.it_value.tv_sec = strtoul(arg, NULL, 0);
		break;
	case 'f':
		ctx->max_fails = strtoull(arg, NULL, 0);
		break;
	case 'g':
		ctx->debug = true;
		break;
	case 'v':
		ctx->verbose = true;
		break;
	case ARGP_KEY_ARG:
		switch (state->arg_num) {
		case 0:
			if (!strcmp(arg, "list-apis"))
				list_apis(ctx);
			if (!strcmp(arg, "list-test-types"))
				list_test_types(ctx);
			ctx->api = arg;
			break;
		case 1:
			ctx->test_type = arg;
			break;
		default:
			/* Too many arguments */
			argp_usage(state);
			break;
		}
		break;
	case ARGP_KEY_END:
		if (state->arg_num < 2) {
			/* Too few arguments */
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
		break;
	}

	return 0;
}

static char *vdsotest_help_filter(int key, const char *text, void *input)
{
	char *str = NULL;

	if (key != ARGP_KEY_HELP_PRE_DOC)
		return (char *)text;

	xasprintf(&str,
		  "where API must be one of:\n"
		  "%s"
		  "and TEST-TYPE must be one of:\n"
		  "%s",
		  api_list,
		  test_type_list);

	return str;
}

static const char vdsotest_args_doc[] = "API TEST-TYPE\n"
	"list-apis\n"
	"list-test-types";

static const struct argp argparser = {
	.options = options,
	.parser = parse,
	.args_doc = vdsotest_args_doc,
	.help_filter = vdsotest_help_filter,
};

void register_testsuite(const struct test_suite *ts)
{
	char *new_api_list;

	xasprintf(&new_api_list, "%s\t%s\n",
		  api_list ? api_list : "", ts->name);
	xfree(api_list);
	api_list = new_api_list;

	if (ts->vdso_names) {
		unsigned int i;

		assert(ts->bind != NULL);

		for (i = 0; ts->vdso_names[i] != NULL; i++) {
			const char *name = ts->vdso_names[i];
			void *func;

			func = get_vdso_sym(name);
			if (!func)
				continue;

			ts->bind(func);
			break;
		}
	}

	hashtable_add(&test_suite_htab, ts->name, ts);
}

int main(int argc, char **argv)
{
	const struct test_suite *ts;
	enum testfunc_result tf_ret;
	struct ctx ctx;
	testfunc_t tf;
	int ret;

	ret = EXIT_SUCCESS;

	ctx_init_defaults(&ctx);

	argp_parse(&argparser, argc, argv, 0, 0, &ctx);

	ts = lookup_ts(ctx.api);
	if (!ts) {
		error(EXIT_FAILURE, 0, "Unknown test suite '%s' specified",
		      ctx.api);
	}

	tf = lookup_tf(ctx.test_type);
	if (!tf) {
		error(EXIT_FAILURE, 0, "Unknown test function '%s' specified",
		      ctx.test_type);
	}

	tf_ret = tf(&ctx, ts);

	if (tf_ret == TF_NOIMPL) {
		printf("%s/%s: unimplemented\n", ctx.api, ctx.test_type);
	} else if (ctx.fails > 0) {
		printf("%s/%s: %llu failures/inconsistencies encountered\n",
		       ctx.api, ctx.test_type, ctx.fails);
		ret = EXIT_FAILURE;
	}

	if (ts->notes)
		ts->notes(&ctx);

	return ret;
}
