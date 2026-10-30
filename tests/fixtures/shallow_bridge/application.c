#include <stdlib.h>
#include "shallow_t.h"
void *exercise(Flexible *f, size_t bytes, Shallow *s, char **pointers,
               Opaque *opaque, IntPtr cookie, IntArray array, int action)
{
    if (bytes != 12 || f->n != 8 || f->data[7] != 8 || s->host[0] != 'H' ||
        (uintptr_t)s->owned != UINT64_MAX || s->token != UINT64_MAX ||
        (uintptr_t)pointers[0] != 1 || (uintptr_t)pointers[1] != UINT64_MAX ||
        ((char *)opaque)[3] != 'd' || cookie[0] != 7 || array[2] != 9)
        return (void *)1;
    char *owned = malloc(16);
    if (!owned) return (void *)2;
    owned[0] = 'q'; s->owned = owned; pointers[0] = owned;
    s->host[0] = 'A'; f->data[7] = 18; ((char *)opaque)[3] = 'D';
    void *result = NULL;
    if (exchange(&result,f,bytes,s,pointers,opaque,cookie,array,action) != SGX_SUCCESS) {
        free(owned); return (void *)3;
    }
    /* The bridge transported the result bits. This actual access checks them. */
    if (*(char *)result != 'q' || s->host[0] != 'J' || f->data[7] != 28 ||
        ((char *)opaque)[3] != '!' || pointers[1] != owned || cookie[0] != 17 || array[2] != 19) {
        free(owned); return (void *)4;
    }
    *(char *)result = 'r';
    if (owned[0] != 'r') { free(owned); return (void *)5; }
    free(owned);
    /* Return the same pointer value to the host, without accessing it again. */
    return result;
}
