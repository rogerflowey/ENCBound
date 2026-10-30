#include "fixture.h"

/* SQLite stores heterogeneous signatures as void (*)(void) and casts back at
 * each call. Both current and saved/default entries are mutable application data.
 * Volatile also keeps same-unit recursive dispatch indirect at frontend O2.
 */
static struct { generic_function current, saved; } volatile table[] = {
    {(generic_function)API(va_mix), 0},
    {(generic_function)API(va_fp), 0},
    {(generic_function)API(va_many_fixed), 0},
    {(generic_function)API(va_cursors), 0},
    {(generic_function)API(va_promotions), 0},
    {(generic_function)API(indirect_recurse), 0},
    {(generic_function)API(va_pointer), 0},
    {(generic_function)API(va_bad), 0},
    {(generic_function)API(indirect_control), 0},
    {(generic_function)API(indirect_remap), 0},
    {(generic_function)API(indirect_identity), 0},
};
generic_function API(callback_get)(unsigned index) { return table[index].current; }
generic_function API(callback_replace)(unsigned index, generic_function replacement)
{
    generic_function before=table[index].current;
    if (!table[index].saved) table[index].saved=before;
    table[index].current=replacement ? replacement : table[index].saved;
    return before;
}
long API(indirect_recurse)(int depth, ...)
{
    va_list ap; va_start(ap, depth);
    long value=depth ? va_arg(ap, long) : 0;
    va_end(ap);
    long (*next)(int, ...)=(long (*)(int, ...))table[5].current;
    return depth ? value+next(depth-1, value+1) : 0;
}
/* fcntl/mremap call shapes, with independently specified fixture behavior. */
int API(indirect_control)(int fd, int cmd, ...)
{
    va_list ap; va_start(ap, cmd);
    int result=fd;
    if (cmd==1) result+=va_arg(ap, int);
    if (cmd==2) { int *p=va_arg(ap, int *); result+=*p; *p=43; }
    va_end(ap); return result;
}
void *API(indirect_remap)(void *old, unsigned long a, unsigned long b, int flags, ...)
{
    va_list ap; va_start(ap, flags);
    void *result=flags ? va_arg(ap, void *) : old;
    va_end(ap); return a+b==12 ? result : 0;
}
/* Frontend O2 infers `returned` on p, as it does for sqlite3_snprintf. */
void *API(indirect_identity)(void *p, int value, ...)
{
    va_list ap; va_start(ap, value);
    int *out=va_arg(ap, int *); *out=value;
    va_end(ap); return p;
}

