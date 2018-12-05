#ifdef CLOCK_TAI
#define CLOCK_ID CLOCK_TAI
#else
#define CLOCK_ID 11
#endif
#define TS_SFX "tai"

#include "clock_gettime_template.c"
#include "clock_getres_template.c"
