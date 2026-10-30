/*
 * ENCBound restart - enclave export script.
 *
 * These are the SDK-required enclave exports. Structure follows Intel SGX SDK
 * 2.26 SampleCode/SampleEnclave/Enclave/Enclave.lds (BSD-3-Clause, Intel
 * Corporation). Step 2 supplements section ownership here.
 */
enclave.so
{
    global:
        g_global_data_sim;
        g_global_data;
        enclave_entry;
        g_peak_heap_used;
        g_peak_rsrv_mem_committed;
    local:
        *;
};
