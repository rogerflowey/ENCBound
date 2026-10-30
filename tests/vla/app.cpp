/* Clang C++ VLA extension, ordinary instrumented constructors/destructors. */
#include <stddef.h>
extern "C" void vla_destroyed(int);
struct Item {
    volatile int value;
    Item():value(7) {}
    ~Item() { vla_destroyed(value); }
};
extern "C" int vla_cpp(size_t n) {
    Item objects[n];
    int sum=0;
    for (size_t i=0;i<n;++i) sum+=objects[i].value;
    return sum;
}
extern "C" int vla_cpp_signed(long x,long y) {
    Item objects[x*y];
    int sum=0;
    for (long i=0;i<x*y;++i) sum+=objects[i].value;
    return sum;
}
