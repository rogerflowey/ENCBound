/* ENCBound step 4 pass sample: stack slots, heap, loads/stores, intrinsics. */
#include <stddef.h>
#include <stdlib.h>

int sum(const int *in, int n)
{
    int acc = 0;
    for (int i = 0; i < n; ++i) {
        acc += in[i];
    }
    return acc;
}

void copy_bytes(char *dst, const char *src, size_t n)
{
    __builtin_memcpy(dst, src, n);
}

void fill_bytes(char *dst, size_t n)
{
    __builtin_memset(dst, 0, n);
}

int *alloc_ints(int n)
{
    return (int *)malloc((size_t)n * sizeof(int));
}

int main(void)
{
    int data[4] = { 1, 2, 3, 4 };
    char buf[8];
    int *heap = alloc_ints(4);
    fill_bytes(buf, sizeof(buf));
    copy_bytes(buf, "abc", 4);
    if (heap != NULL) {
        heap[0] = sum(data, 4);
        free(heap);
    }
    return buf[0];
}
