/* Original fixture; readers and native protection controls reuse tests/pass. */
#include "../pass/variadics_fixture.h"
typedef void (*generic_function)(void);
generic_function API(callback_get)(unsigned);
generic_function API(callback_replace)(unsigned, generic_function);
long API(indirect_case)(unsigned char *, int);
long API(indirect_recurse)(int, ...);
int API(indirect_control)(int, int, ...);
void *API(indirect_remap)(void *, unsigned long, unsigned long, int, ...);
void *API(indirect_identity)(void *, int, ...);

