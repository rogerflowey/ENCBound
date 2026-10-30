// Application-owned SDK RTTI, compiled entirely through the application pass.
// The SDK algorithms and the local adaptations are recorded in sdk/pins.json.
#include <typeinfo>
#include <new>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include "sdk/typeinfo.cc"
#include "sdk/dynamic_cast.cc"

namespace std {
exception::exception() noexcept = default;
exception::exception(const exception &) noexcept = default;
exception &exception::operator=(const exception &) noexcept = default;
exception::~exception() = default;
const char *exception::what() const noexcept { return "std::exception"; }
bad_alloc::bad_alloc() noexcept = default;
bad_alloc::bad_alloc(const bad_alloc &) noexcept = default;
bad_alloc &bad_alloc::operator=(const bad_alloc &) noexcept = default;
bad_alloc::~bad_alloc() = default;
const char *bad_alloc::what() const noexcept { return "cxxrt::bad_alloc"; }
bad_cast::bad_cast() noexcept = default;
bad_cast::~bad_cast() noexcept = default;
const char *bad_cast::what() const noexcept { return "std::bad_cast"; }
bad_typeid::bad_typeid() noexcept = default;
bad_typeid::~bad_typeid() noexcept = default;
const char *bad_typeid::what() const noexcept { return "std::bad_typeid"; }
}


struct Match { void *value; uintptr_t matched; };
extern "C" Match __encbound_app_eh_match(const void *thrown_type, const void *catch_type, void *payload) {
    using __cxxabiv1::__shim_type_info;
    auto *from=static_cast<const __shim_type_info *>(thrown_type);
    auto *to=static_cast<const __shim_type_info *>(catch_type);
    void *value=from->__is_pointer_p() ? *static_cast<void **>(payload) : payload;
    if (!to || from==to) return {value,1};
    if (thrown_type==&typeid(std::nullptr_t) && to->__is_pointer_p()) return {nullptr,1};
    if (to->__do_catch(from,&value,1)) return {value,1};
    return {nullptr,0};
}

extern "C" [[noreturn]] void __encbound_app_bad_cast() { throw std::bad_cast(); }
extern "C" [[noreturn]] void __encbound_app_bad_typeid() { throw std::bad_typeid(); }
extern "C" void *__encbound_app_new(size_t size) {
    if (void *p=::operator new(size,std::nothrow)) return p;
    throw std::bad_alloc();
}
extern "C" void *__encbound_app_new_aligned(size_t size, size_t alignment) {
    if (void *p=::operator new(size,static_cast<std::align_val_t>(alignment),std::nothrow)) return p;
    throw std::bad_alloc();
}
