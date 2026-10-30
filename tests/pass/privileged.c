/* ENCBound step 4 rejection sample: app call to a runtime helper must fail. */
extern long encbound_stack_mint(void *slot, unsigned long size);

long forge(void *slot)
{
    return encbound_stack_mint(slot, 16);
}
