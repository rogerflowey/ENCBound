/* ENCBound step 4 rejection sample: an indirect call must fail the build. */
int apply(int (*f)(int), int x)
{
    return f(x);
}
