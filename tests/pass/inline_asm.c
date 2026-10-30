/* ENCBound step 4 rejection sample: inline asm must fail the build. */
int read_tsc_low(void)
{
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (int)(lo ^ hi);
}
