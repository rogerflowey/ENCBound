#ifndef ENCBOUND_LIFECYCLE_TEST_OBJECTS_H
#define ENCBOUND_LIFECYCLE_TEST_OBJECTS_H
void note(int);
struct Item {
    int id;
    int *value;
    __attribute__((noinline)) Item(int n) : id(n), value(new int(n*10)) {
#if LIFECYCLE_FAULT == 1
        *(volatile unsigned short *)((char *)this+15)=999;
#endif
        note(n);
    }
    __attribute__((noinline)) ~Item() {
#if LIFECYCLE_FAULT == 2
        *(volatile unsigned short *)((char *)this+15)=999;
#endif
        note(100+id); delete value; value = nullptr;
    }
    __attribute__((noinline)) int read() { return *value; }
};
inline Item &shared() { static Item object(6); return object; }
template<class T> struct Box { inline static Item object{7}; };
// An ODR pointer initializer needs its fixup in the same selected COMDAT as
// the pointer storage. It must target the one selected inline variable.
inline Item *box_pointer = &Box<int>::object;
int other_unit();
#endif
