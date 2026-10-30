/* ENCBound step 4 rejection sample: application TLS must fail admission. */
__thread int tls_counter;

int bump(void)
{
    tls_counter += 1;
    return tls_counter;
}
