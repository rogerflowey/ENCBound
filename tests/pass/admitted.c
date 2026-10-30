/* ENCBound step 4 admission sample: a listed cross-TU app symbol is admitted. */
extern int app_helper(int);

int call_helper(int x)
{
    return app_helper(x);
}
