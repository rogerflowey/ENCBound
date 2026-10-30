/* ENCBound step 4 rejection sample: setjmp/longjmp must fail the build. */
#include <setjmp.h>

static jmp_buf env;

int jump_away(void)
{
    return setjmp(env);
}
