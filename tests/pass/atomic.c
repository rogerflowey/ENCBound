/* ENCBound step 4 pass rejection sample: an atomic load must fail the build. */
int atomic_load(int *p)
{
    return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}
