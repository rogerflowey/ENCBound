/* ENCBound step 4 rejection sample: an atomicrmw must fail the build. */
int fetch_add(int *p)
{
    return __atomic_fetch_add(p, 1, __ATOMIC_SEQ_CST);
}
