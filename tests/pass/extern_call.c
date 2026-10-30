/* ENCBound step 4 rejection sample: an unapproved external call must fail. */
extern int not_admitted(int);

int call_extern(int x)
{
    return not_admitted(x);
}
