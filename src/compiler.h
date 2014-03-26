#ifndef VDSOTEST_COMPILER_H
#define VDSOTEST_COMPILER_H

#define __constructor  __attribute__((constructor))
#define __printf(a, b) __attribute__((format(printf, a, b)))

#endif
