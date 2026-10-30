#include <stdint.h>
char buffer[24] = "abcdef";
char other[24] = "zyx";
char zero_buffer[24];
unsigned char big_buffer[65537];
char *cursor = buffer + 4;
char *pointers[] = {buffer, buffer + 23, buffer + 24};
struct __attribute__((packed)) packed_record { char marker; char *pointer; };
struct packed_record packed = {7, buffer + 5};
struct node { struct node *next; int value; };
extern struct node second;
struct node first = {&second, 11};
struct node second = {&first, 13};
extern int external_counter;
extern char *external_pointer;
static unsigned sessions;

int globals_run(void) {
    if (*cursor != (sessions ? 'b' : 'e') || packed.marker!=7 || *packed.pointer!='f' ||
        pointers[0]!=buffer || pointers[1]!=buffer+23 || pointers[2]!=buffer+24 ||
        first.next!=&second || second.next!=&first || first.next->value!=13 ||
        zero_buffer[0] || big_buffer[65536] || external_pointer!=buffer+2 || *external_pointer!='c') return -1;
    cursor=buffer+1;
    return ++sessions + ++external_counter;
}
uintptr_t globals_pointer(int which) { return (uintptr_t)(which ? other : buffer); }
int globals_read(uintptr_t p) { return *(volatile unsigned char *)p; }
int globals_index(int i) { return ((volatile unsigned char *)buffer)[i]; }
int globals_crossing(void) {
    return *(volatile unsigned short *)(buffer + 31);
}
