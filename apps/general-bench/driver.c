/* Application-domain harness. All allocations, initialization, kernels and
 * result copying are instrumented in protected profiles. No workload globals. */
#include "bench.h"
#include <stdlib.h>
#include <string.h>

static int once(int which, double *out)
{
    int i, j;
    if (which == 0) {
        int result = test_lists();
        out[0] = result;
        return result == 100 ? 0 : 2;
    }
    if (which == 1) {
        double *a = malloc((SORT_N+1)*sizeof(double));
        long seed = 42;
        if (!a) return 3;
        for (i=1; i<=SORT_N; ++i) {
            seed = (seed*3877+29573)%139968;
            a[i] = (double)seed/139968;
        }
        benchmark_heapsort(SORT_N, a);
        memcpy(out, a+1, SORT_N*sizeof(double));
        free(a);
        return 0;
    }
    if (which == 2) {
        double (*a)[ATAX_N] = malloc(ATAX_N*ATAX_N*sizeof(double));
        double *x = malloc(ATAX_N*sizeof(double));
        double *tmp = malloc(ATAX_N*sizeof(double));
        if (!a || !x || !tmp) { free(a); free(x); free(tmp); return 3; }
        for (i=0; i<ATAX_N; ++i) {
            x[i] = 1+(double)i/ATAX_N;
            for (j=0; j<ATAX_N; ++j) a[i][j] = (double)((i+j)%ATAX_N)/(5*ATAX_N);
        }
        kernel_atax(ATAX_N, ATAX_N, a, x, out, tmp);
        free(a); free(x); free(tmp);
        return 0;
    }
    if (which == 3) {
        double (*a)[GEMM_N] = malloc(GEMM_N*GEMM_N*sizeof(double));
        double (*b)[GEMM_N] = malloc(GEMM_N*GEMM_N*sizeof(double));
        double (*c)[GEMM_N] = (void *)out;
        if (!a || !b) { free(a); free(b); return 3; }
        for (i=0; i<GEMM_N; ++i) for (j=0; j<GEMM_N; ++j) {
            a[i][j] = (double)(i*(j+1)%GEMM_N)/GEMM_N;
            b[i][j] = (double)(i*(j+2)%GEMM_N)/GEMM_N;
            c[i][j] = (double)((i*j+1)%GEMM_N)/GEMM_N;
        }
        kernel_gemm(GEMM_N,GEMM_N,GEMM_N,1.5,1.2,c,a,b);
        free(a); free(b);
        return 0;
    }
    if (which == 4) {
        double (*a)[JACOBI_N] = (void *)out;
        double (*b)[JACOBI_N] = malloc(JACOBI_N*JACOBI_N*sizeof(double));
        if (!b) return 3;
        for (i=0; i<JACOBI_N; ++i) for (j=0; j<JACOBI_N; ++j) {
            a[i][j] = ((double)i*(j+2)+2)/JACOBI_N;
            b[i][j] = ((double)i*(j+3)+3)/JACOBI_N;
        }
        kernel_jacobi_2d(JACOBI_STEPS,JACOBI_N,a,b);
        free(b);
        return 0;
    }
    return 1;
}

int bench_run(int which, int repetitions, unsigned char *output, size_t output_size)
{
    if (which < 0 || which > 4 || repetitions < 1 || repetitions > 100000 ||
        output_size != bench_output_size(which) || !output) return 1;
    for (int i=0; i<repetitions; ++i) {
        int rc = once(which, (double *)output);
        if (rc) return rc;
    }
    return 0;
}
