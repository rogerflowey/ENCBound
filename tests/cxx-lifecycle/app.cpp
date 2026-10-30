#include "objects.h"
static volatile int events[64];
static unsigned count;
__attribute__((destructor(201))) static void finish_array() { note(200); }
void note(int n) { if (count < 64) events[count++] = n; }
Item first __attribute__((init_priority(200))) (1);
Item array[2] __attribute__((init_priority(300))) = {Item(3),Item(4)};
Item last __attribute__((init_priority(400))) (2);
static Item &local() { static Item object(5); return object; }
extern "C" int exercise(int action) {
    if (action == 0) {
        if (count != 5 || events[0]!=1 || events[1]!=3 || events[2]!=4 || events[3]!=2 || events[4]!=7) return -1;
        if (first.read()!=10 || array[0].read()!=30 || array[1].read()!=40 || last.read()!=20) return -2;
        if (local().read()!=50 || shared().read()!=60 || other_unit()!=130 || box_pointer->read()!=70) return -3;
        if (count!=7 || events[5]!=5 || events[6]!=6) return -4;
        return 170;
    }
    if (action == 1) {
        if (count!=14) return -5;
        const int expected[7] = {106,105,107,102,104,103,101};
        for (unsigned i=0;i<7;++i) if (events[7+i]!=expected[i]) return -6;
        return 0;
    }
    if (action == 3) return count==15 && events[14]==200 ? 0 : -8;
    // Repeat accesses without running registration or construction again.
    if (count!=7 || local().read()+shared().read()+other_unit()!=240 || count!=7) return -7;
    return 240;
}
extern "C" unsigned long object_bits() { return (unsigned long)&shared(); }
extern "C" void checked_store(unsigned long p) { *(volatile int *)p=999; }
