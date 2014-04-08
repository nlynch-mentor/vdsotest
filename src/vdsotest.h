#ifndef VDSOTEST_H
#define VDSOTEST_H

#include <errno.h>
#include <error.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "compiler.h"
#include "util.h"

/* Valgrind uses SIGRTMAX.  Just try to use something in the middle of
 * the range.
 */
#define TIMER_SIGNO (SIGRTMIN + ((SIGRTMAX - SIGRTMIN) / 2))
#define SUBTIMER_SIGNO (TIMER_SIGNO + 1)

struct ctx {
	volatile sig_atomic_t should_stop;
	struct itimerspec duration;
	timer_t timer;
	cpu_set_t cpus_allowed;
	unsigned long long max_fails;
	unsigned long long fails;
	const char *api;
	const char *test_type;
	bool debug;
	bool verbose;
};

struct bench_interval {
	uint64_t calls;
	struct timespec begin;
	struct timespec end;
	uint64_t duration_nsec;
	uint64_t calls_per_sec;
};

struct bench_results {
	struct bench_interval vdso_interval;
	struct bench_interval sys_interval;
};

static inline void __bench_interval_begin(struct bench_interval *ival)
{
	int err;

	err = clock_gettime(CLOCK_MONOTONIC, &ival->begin);
	if (err)
		error(EXIT_FAILURE, errno, "clock_gettime");
}

#define bench_interval_begin(ival, calls)	\
	do {					\
		calls = 0;			\
		__bench_interval_begin(ival);	\
	} while (0)

static inline void bench_interval_end(struct bench_interval *ival, uint64_t calls)
{
	int err;

	err = clock_gettime(CLOCK_MONOTONIC, &ival->end);
	if (err)
		error(EXIT_FAILURE, errno, "clock_gettime");
	ival->calls = calls;
	ival->duration_nsec = timespec_delta_nsec(&ival->begin, &ival->end);
	ival->calls_per_sec = (ival->calls * NSEC_PER_SEC) / ival->duration_nsec;
}

struct test_suite {
	const char *name; /* name of the API under test */

	/* Estimate speedup obtained by using vDSO implementation vs syscall */
	void (*bench)(struct ctx *ctx, struct bench_results *res);

	/* Check for inconsistencies between vDSO and syscall
	 * implemenations, usually by rapidly switching between the
	 * two modes and comparing results obtained.
	 *
	 * FIXME: distinguish between self-consistency (vDSO-only) and
	 * vDSO vs kernel consistency.  Or assume that doing vDSO vs
	 * kernel will catch everything.
	 */
	void (*verify)(struct ctx *ctx);

	/* Check for ABI inconsistencies, within reason - e.g. vDSO
	 * may get SIGSEGV where syscall may return EFAULT.
	 */
	void (*abi)(struct ctx *ctx);

	/* Hook for printing any notes at the end of test run
	 * e.g. vDSO not detected
	 */
	void (*notes)(struct ctx *ctx);
};

void register_testsuite(const struct test_suite *ts);

void ctx_start_timer(struct ctx *ctx);
void ctx_cleanup_timer(struct ctx *ctx);

static inline bool test_should_stop(const struct ctx *ctx)
{
	return ctx->should_stop;
}

void log_failure(struct ctx *ctx, const char *fmt, ...) __printf(2, 3);
void verbose(const struct ctx *ctx, const char *fmt, ...) __printf(2, 3);

void __debug(const struct ctx *ctx, const char *fn, int line,
	     const char *fmt, ...) __printf(4, 5);
#define debug(ctx, arg...) __debug((ctx), __func__, __LINE__, ## arg)

struct syscall_result {
	int sr_ret;
	int sr_errno;
};

static inline void record_syscall_result(struct syscall_result *res,
					 int sr_ret, int sr_errno)
{
	/* Calling the vDSO directly instead of through libc can lead to:
	 * - The vDSO code punts to the kernel (e.g. unrecognized clock id).
	 * - The kernel returns an error (e.g. -22 (-EINVAL))
	 * So we need to recognize this situation and fix things up.
	 * Fortunately we're dealing only with syscalls that return -ve values
	 * on error.
	 */
	if (sr_ret < 0 && sr_errno == 0) {
		sr_errno = -sr_ret;
		sr_ret = -1;
	}

	*res = (struct syscall_result) {
		.sr_ret = sr_ret,
		.sr_errno = sr_errno,
	};
}

static inline void syscall_prepare(void)
{
	errno = 0;
}

struct child_params {
	const char *desc; /* description for diagnostic prints */
	void (*func)(void *arg, struct syscall_result *res);
	void *arg;
	struct syscall_result syscall_result; /* expected syscall results */
	int expected_ret;
	int expected_errno;
	struct signal_set signal_set;  /* expected termination signals */
};

void run_as_child(struct ctx *ctx, const struct child_params *parms);

#endif
