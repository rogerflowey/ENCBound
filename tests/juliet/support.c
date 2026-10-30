/* Juliet pilot output adaptation, compiled in the APPLICATION domain.
 * Reads every character/field before forwarding scalar observations. This
 * replaces formatting in upstream io.c, never the vulnerable test operation.
 * There is deliberately no raw pointer-taking print service.
 */
#include "std_testcase.h"
extern void juliet_emit(uint32_t kind, uint64_t value);

void printLine(const char *line)
{
    if (line != NULL) {
        juliet_emit(1, 0);
        while (*line != '\0') {
            juliet_emit(2, (unsigned char)*line++);
        }
        juliet_emit(3, 0);
    }
}
void printIntLine(int value) { juliet_emit(4, (uint64_t)(int64_t)value); }
void printLongLongLine(int64_t value) { juliet_emit(5, (uint64_t)value); }
void printStructLine(const twoIntsStruct *value)
{
    juliet_emit(6, (uint64_t)(int64_t)value->intOne);
    juliet_emit(7, (uint64_t)(int64_t)value->intTwo);
}
void printDoubleLine(double value)
{
    union { double d; uint64_t u; } bits;
    bits.d = value;
    juliet_emit(8, bits.u);
}
