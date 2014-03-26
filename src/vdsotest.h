#ifndef VDSOTEST_H
#define VDSOTEST_H

#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

struct ctx {
	volatile sig_atomic_t expired;
	struct itimerspec duration;
	cpu_set_t cpus_allowed;
};

struct bench_results {
	int dummy;
};

struct test_suite {
	const char *name; /* name of the API under test */

	/* Estimate speedup obtained by using vDSO implementation vs syscall */
	int (*bench)(struct ctx *ctx, struct bench_results *res);

	/* Check for inconsistencies between vDSO and syscall
	 * implemenations, usually by rapidly switching between the
	 * two modes and comparing results obtained.
	 *
	 * FIXME: distinguish between self-consistency (vDSO-only) and
	 * vDSO vs kernel consistency.  Or assume that doing vDSO vs
	 * kernel will catch everything.
	 */
	int (*verify)(struct ctx *ctx);

	/* Check for ABI inconsistencies, within reason - e.g. vDSO
	 * may get SIGSEGV where syscall may return EFAULT.
	 */
	int (*abi)(struct ctx *ctx);
};

void register_testsuite(const struct test_suite *ts);

void ctx_start_timer(struct ctx *ctx);

static inline bool ctx_timer_expired(const struct ctx *ctx)
{
	return ctx->expired;
}

#endif
