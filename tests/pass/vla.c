/* ENCBound step 4 rejection sample: a VLA/dynamic alloca must fail the build.
 * The address escapes so optimization cannot eliminate the dynamic alloca. */
int *stack_ptr(int n)
{
    int a[n];
    return a;
}
