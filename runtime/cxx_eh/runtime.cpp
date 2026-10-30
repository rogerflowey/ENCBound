/* 
 * Copyright 2010-2011 PathScale, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Capability-aware application ABI adaptation of the Intel SDK 2.26
 * PathScale exception.cc protocol. Copyright 2010-2011 PathScale, Inc.
 * The original BSD-2-Clause notice/disclaimer is in COPYING.PathScale.
 * Source and unchanged DWARF/header pins are in sdk-pins.json.
 *
 * Keep the SDK unwinder, private __cxa_exception layout and two-phase LSDA
 * dispatch. Replace payload adjacency with an explicit private association.
 * SDK-internal C++ exceptions retain their original symbols/state/class.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "cxxabi.h"
#include "dwarf_eh.h"
#include "runtime.h"
extern "C" {
#include "encbound_runtime.h"
#include "encbound_platform.h"
}

using __cxxabiv1::__cxa_exception;
namespace {
constexpr uint64_t app_class=EXCEPTION_CLASS('E','N','C','B','C','+','+','\0');
struct Node {
    __cxa_exception header;
    void *payload;
    size_t requested;
    size_t rounded;
    Node *next;
    bool thrown;
};
// Private state for the project's serial execution model. It is distinct from
// SDK cxx_thread_info; no application TLS or cross-call exception retention.
Node *live;
__cxa_exception *caught;
unsigned uncaught;
size_t live_count, peak_count, live_bytes, peak_bytes;
size_t live_rounded,peak_rounded,total_allocations;

[[noreturn]] void fail() { encbound_abort(ENCBOUND_ERR_STATE); }
Node *by_payload(void *p) {
    for (Node *n=live;n;n=n->next) if (n->payload==p) return n;
    fail();
}
Node *by_token(const void *p) {
    for (Node *n=live;n;n=n->next) if (&n->header.unwindHeader==p && n->thrown) return n;
    fail();
}
Node *by_header(__cxa_exception *h) {
    for (Node *n=live;n;n=n->next) if (&n->header==h) return n;
    fail();
}
void check_payload(Node *n) {
    encbound_require((uintptr_t)n->payload,n->requested,ENCBOUND_ACCESS_READ);
}
struct Match { void *value; uintptr_t matched; };
}
extern "C" Match __encbound_app_eh_match(const void *,const void *,void *);
extern "C" void encbound_eh_free_exception(void *);

namespace {
void cleanup(_Unwind_Reason_Code, _Unwind_Exception *e) {
    encbound_eh_free_exception(by_token(e)->payload);
}
// The following lookup and two-phase dispatch are the SDK's x86-64 Itanium
// protocol. Type traversal is an instrumented application call, not raw SDK
// virtual dispatch into data supplied by the application.
const void *type_entry(_Unwind_Context *context,dwarf_eh_lsda *lsda,int filter) {
    dw_eh_ptr_t record=lsda->type_table-dwarf_size_of_fixed_size_field(lsda->type_table_encoding)*filter;
    dw_eh_ptr_t start=record;
    int64_t value=read_value(lsda->type_table_encoding,&record);
    return value ? reinterpret_cast<const void *>(resolve_indirect_value(context,lsda->type_table_encoding,value,start)) : nullptr;
}
enum Handler { none, cleanup_handler, catch_handler };
Handler action_record(_Unwind_Context *context,dwarf_eh_lsda *lsda,dw_eh_ptr_t record,
                      Node *n,unsigned long *selector,void **adjusted) {
    if (!record) return cleanup_handler;
    Handler found=none;
    while (record) {
        int filter=read_sleb128(&record);
        dw_eh_ptr_t displacement_base=record;
        int displacement=read_sleb128(&record);
        record=displacement ? displacement_base+displacement : nullptr;
        if (filter>0) {
            check_payload(n);
            Match match=__encbound_app_eh_match(n->header.exceptionType,type_entry(context,lsda,filter),n->payload);
            if (match.matched) { *selector=filter; *adjusted=match.value; return catch_handler; }
        } else if (filter==0) {
            *selector=0; found=cleanup_handler;
        } else fail(); // Dynamic exception specifications are rejected at admission.
    }
    return found;
}
[[noreturn]] void raise(Node *n,bool rethrow) {
    if (uncaught==UINT_MAX) fail();
    ++uncaught;
    if (rethrow) _Unwind_Resume_or_Rethrow(&n->header.unwindHeader);
    else _Unwind_RaiseException(&n->header.unwindHeader);
    // Includes an uncaught application exception. No SDK/reporting traversal
    // of the protected payload, and no catchable ENCBound protection failures.
    fail();
}
}

extern "C" void *encbound_eh_allocate_exception(size_t bytes) {
    if (!bytes) fail();
    Node *n=static_cast<Node *>(calloc(1,sizeof(Node)));
    if (!n) encbound_abort(ENCBOUND_ERR_DEPLETED);
    n->payload=encbound_malloc(bytes);
    if (!n->payload) { free(n); encbound_abort(ENCBOUND_ERR_DEPLETED); }
    n->requested=bytes; n->next=live; live=n;
    n->rounded=size_t(1)<<((uintptr_t)n->payload>>ENCBOUND_RADIX_SHIFT);
    ++live_count; live_bytes+=bytes;
    ++total_allocations;live_rounded+=n->rounded;
    if(live_rounded>peak_rounded)peak_rounded=live_rounded;
    if (live_count>peak_count) peak_count=live_count;
    if (live_bytes>peak_bytes) peak_bytes=live_bytes;
    return n->payload;
}
extern "C" void encbound_eh_free_exception(void *payload) {
    Node *n=by_payload(payload);
    if (n->header.handlerCount) fail();
    check_payload(n);
    // The compiler supplies a verified terminating callback wrapper. All
    // destructor body accesses still use the original application capability.
    if (n->header.exceptionDestructor) n->header.exceptionDestructor(payload);
    Node **link=&live;
    while (*link!=n) { if (!*link) fail(); link=&(*link)->next; }
    *link=n->next;
    --live_count; live_bytes-=n->requested;
    live_rounded-=n->rounded;
    encbound_free(payload); free(n);
}
extern "C" [[noreturn]] void encbound_eh_throw(void *payload,void *type,void (*destroy)(void *)) {
    Node *n=by_payload(payload);
    if (n->thrown || !type) fail();
    check_payload(n);
    n->thrown=true;
    n->header.referenceCount=1;
    n->header.exceptionType=static_cast<std::type_info *>(type);
    n->header.exceptionDestructor=destroy;
    n->header.unwindHeader.exception_class=app_class;
    n->header.unwindHeader.exception_cleanup=cleanup;
    raise(n,false);
}
extern "C" void *encbound_eh_begin_catch(void *token) {
    Node *n=by_token(token);
    __cxa_exception *e=&n->header;
    if (!uncaught || e->handlerCount==INT_MAX || e->handlerCount==INT_MIN) fail();
    --uncaught;
    if (!e->handlerCount) { e->nextException=caught; caught=e; }
    if (e->handlerCount<0) e->handlerCount=-e->handlerCount+1;
    else ++e->handlerCount;
    return e->adjustedPtr;
}
extern "C" void *encbound_eh_get_exception_ptr(void *token) {
    return by_token(token)->header.adjustedPtr;
}
extern "C" void encbound_eh_end_catch() {
    Node *n=by_header(caught);
    __cxa_exception *e=&n->header;
    bool destroy=e->handlerCount>0;
    if (!e->handlerCount) fail();
    if (destroy) --e->handlerCount; else ++e->handlerCount;
    if (!e->handlerCount) {
        caught=e->nextException;
        if (destroy) encbound_eh_free_exception(n->payload);
    }
}
extern "C" [[noreturn]] void encbound_eh_rethrow() {
    Node *n=by_header(caught);
    if (n->header.handlerCount<=0) fail();
    n->header.handlerCount=-n->header.handlerCount;
    raise(n,true);
}
extern "C" [[noreturn]] void encbound_eh_terminate(void *token) {
    (void)by_token(token);
    fail();
}
extern "C" int encbound_eh_uncaught_exceptions() { return static_cast<int>(uncaught); }

extern "C" _Unwind_Reason_Code encbound_eh_personality(int version,_Unwind_Action actions,
                    uint64_t exceptionClass,_Unwind_Exception *exceptionObject,_Unwind_Context *context) {
    if (version!=1 || exceptionClass!=app_class || (actions&_UA_FORCE_UNWIND)) fail();
    Node *n=by_token(exceptionObject);
    __cxa_exception *ex=&n->header;
    auto *lsda_addr=reinterpret_cast<unsigned char *>(_Unwind_GetLanguageSpecificData(context));
    if (!lsda_addr) return _URC_CONTINUE_UNWIND;
    dwarf_eh_action action={};
    unsigned long selector=0;
    if (actions&_UA_SEARCH_PHASE) {
        dwarf_eh_lsda lsda=parse_lsda(context,lsda_addr);
        if (!dwarf_eh_find_callsite(context,&lsda,&action)) {
            ex->catchTemp=nullptr;
            return _URC_HANDLER_FOUND; // noexcept/exception through a cleanup
        }
        Handler found=action_record(context,&lsda,action.action_record,n,&selector,&ex->adjustedPtr);
        if (found!=catch_handler) return _URC_CONTINUE_UNWIND;
        ex->handlerSwitchValue=selector; ex->catchTemp=action.landing_pad;
        ex->languageSpecificData=reinterpret_cast<const char *>(lsda_addr);
        ex->actionRecord=reinterpret_cast<const char *>(action.action_record);
        return _URC_HANDLER_FOUND;
    }
    if (!(actions&_UA_HANDLER_FRAME)) {
        dwarf_eh_lsda lsda=parse_lsda(context,lsda_addr);
        dwarf_eh_find_callsite(context,&lsda,&action);
        if (!action.landing_pad) return _URC_CONTINUE_UNWIND;
        Handler found=action_record(context,&lsda,action.action_record,n,&selector,&ex->adjustedPtr);
        if (found!=cleanup_handler) return _URC_CONTINUE_UNWIND;
    } else {
        if (!ex->catchTemp) fail();
        selector=ex->handlerSwitchValue; action.landing_pad=static_cast<dw_eh_ptr_t>(ex->catchTemp);
        ex->catchTemp=nullptr; ex->handlerSwitchValue=0;
    }
    _Unwind_SetIP(context,reinterpret_cast<uintptr_t>(action.landing_pad));
    _Unwind_SetGR(context,__builtin_eh_return_data_regno(0),reinterpret_cast<uintptr_t>(exceptionObject));
    _Unwind_SetGR(context,__builtin_eh_return_data_regno(1),selector);
    return _URC_INSTALL_CONTEXT;
}

// Trusted diagnostic API; never admitted by the application compiler.
extern "C" encbound_eh_stats_t encbound_eh_stats() {
    return {live_count,peak_count,live_bytes,peak_bytes,sizeof(Node),live_rounded,
            peak_rounded,total_allocations,offsetof(__cxa_exception,unwindHeader)};
}
extern "C" void encbound_eh_boundary_clean() {
    if (live || caught || uncaught || live_count || live_bytes || live_rounded) fail();
}
