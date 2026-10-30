#include "objects.h"
__attribute__((noinline)) int other_unit() {
    return shared().read() + box_pointer->read();
}
