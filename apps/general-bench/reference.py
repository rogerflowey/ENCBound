#!/usr/bin/env python3
"""Independent full-output oracles; Python double arithmetic, no benchmark imports."""
from pathlib import Path
import struct
import sys

NAMES = ['lists','heapsort','atax','gemm','jacobi']

def references():
    yield [100.0]
    seed = 42
    values = []
    for _ in range(4096):
        seed = (seed*3877+29573)%139968
        values.append(seed/139968)
    yield sorted(values)
    n = 128
    a = [[((i+j)%n)/(5*n) for j in range(n)] for i in range(n)]
    x = [1+i/n for i in range(n)]
    tmp = []
    for row in a:
        v = 0.0
        for j in range(n): v += row[j]*x[j]
        tmp.append(v)
    y = [0.0]*n
    for i in range(n):
        for j in range(n): y[j] += a[i][j]*tmp[i]
    yield y
    n = 48
    a = [[(i*(j+1)%n)/n for j in range(n)] for i in range(n)]
    b = [[(i*(j+2)%n)/n for j in range(n)] for i in range(n)]
    c = [[((i*j+1)%n)/n for j in range(n)] for i in range(n)]
    # Different loop nesting; each output retains the specified summation order.
    for i in range(n):
        for j in range(n):
            v = c[i][j]*1.2
            for k in range(n): v += (1.5*a[i][k])*b[k][j]
            c[i][j] = v
    yield [v for row in c for v in row]
    n = 64
    a = [[(i*(j+2)+2)/n for j in range(n)] for i in range(n)]
    b = [[(i*(j+3)+3)/n for j in range(n)] for i in range(n)]
    for _ in range(8):
        for src,dst in [(a,b),(b,a)]:
            for i in range(1,n-1):
                for j in range(1,n-1):
                    dst[i][j] = 0.2*(src[i][j]+src[i][j-1]+src[i][j+1]+src[i+1][j]+src[i-1][j])
    yield [v for row in a for v in row]

if __name__ == '__main__':
    dest=Path(sys.argv[1]); dest.mkdir(parents=True,exist_ok=True)
    for name,values in zip(NAMES,references()):
        data=struct.pack('<'+'d'*len(values),*values)
        (dest/(name+'.bin')).write_bytes(data)
