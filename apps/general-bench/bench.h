#ifndef GENERAL_BENCH_H
#define GENERAL_BENCH_H
#include <stddef.h>
#define SORT_N 4096
#define ATAX_N 128
#define GEMM_N 48
#define JACOBI_N 64
#define JACOBI_STEPS 8
#define OUTPUT_BYTES (SORT_N * sizeof(double))
static inline size_t bench_output_size(int which)
{
    if (which == 0) return sizeof(double);
    if (which == 1) return SORT_N*sizeof(double);
    if (which == 2) return ATAX_N*sizeof(double);
    if (which == 3) return GEMM_N*GEMM_N*sizeof(double);
    if (which == 4) return JACOBI_N*JACOBI_N*sizeof(double);
    return 0;
}
int test_lists(void);
void benchmark_heapsort(int n, double *a);
void kernel_atax(int m, int n, double a[ATAX_N][ATAX_N], double *x,
                 double *y, double *tmp);
void kernel_gemm(int ni, int nj, int nk, double alpha, double beta,
                 double c[GEMM_N][GEMM_N], double a[GEMM_N][GEMM_N],
                 double b[GEMM_N][GEMM_N]);
void kernel_jacobi_2d(int steps, int n, double a[JACOBI_N][JACOBI_N],
                      double b[JACOBI_N][JACOBI_N]);
#ifndef SGX_HOST
int bench_run(int which, int repetitions, unsigned char *out, size_t output_size);
#endif
#endif
