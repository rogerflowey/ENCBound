"""Read-only GDB observer for the pinned SDK's benchmark heap allocations.

Executed inside GDB by memory.py, after entry to sgx_bench_run. No inferior
function calls, SDK interposition, or application/runtime modifications.
"""
import json
import gdb

live_sdk = {}
events = []
sdk_events = []
errors = []
counts = dict(sdk_allocations=0, sdk_frees=0, protected_allocations=0,
              protected_frees=0)
protected = bool(gdb.parse_and_eval('$memory_protected'))
node_size = int(gdb.parse_and_eval('sizeof(g_root)')) if protected else 0


def integer(register):
    return int(gdb.parse_and_eval(register))


def chunk_size(pointer, requested):
    # SDK 2.26 dlmalloc: mem2chunk(p) = p - 2*sizeof(size_t); head is
    # its second word. FLAG_BITS is 7. Inspect the actual allocated chunk,
    # including allocator rounding/headers; do not estimate from request size.
    head = int.from_bytes(bytes(gdb.selected_inferior().read_memory(pointer-8, 8)),
                          'little')
    size = head & ~7
    if not head & 2 or size < requested + 8 or size % 16:
        raise RuntimeError('unexpected SDK allocated-chunk header')
    return size


def snapshot(kind):
    pairs = set()
    requested = rounded = objects = 0
    if protected:
        def walk(node, order):
            nonlocal requested, rounded, objects
            children = node['children']
            if int(children):
                address = int(children)
                if address in pairs:
                    raise RuntimeError('duplicate allocator child pair')
                pairs.add(address)
                if address not in live_sdk or live_sdk[address][0] != 2*node_size:
                    raise RuntimeError('unobserved allocator metadata allocation')
                walk(children[0], order-1)
                walk(children[1], order-1)
            elif int(node['requested']):
                requested += int(node['requested'])
                rounded += 1 << order
                objects += 1
        walk(gdb.parse_and_eval('g_root'), integer('g_max_order'))
    else:
        requested = sum(v[0] for v in live_sdk.values())
        objects = len(live_sdk)
    sdk_requested = sum(v[0] for v in live_sdk.values())
    sdk_chunks = sum(v[1] for v in live_sdk.values())
    metadata_payload = len(pairs)*2*node_size
    metadata_chunks = sum(live_sdk[p][1] for p in pairs)
    startup = [v for v in live_sdk.values() if v[2] == 'init_vrdl'] if protected else []
    startup_requested = sum(v[0] for v in startup)
    startup_chunks = sum(v[1] for v in startup)
    events.append(dict(event=kind, sdk_event_count=len(sdk_events),
                       requested=requested, rounded=rounded,
                       live_objects=objects, sdk_requested=sdk_requested,
                       sdk_chunks=sdk_chunks, metadata_payload=metadata_payload,
                       metadata_chunks=metadata_chunks,
                       startup_requested=startup_requested, startup_chunks=startup_chunks,
                       startup_objects=len(startup),
                       workload_active_heap_bytes=rounded+sdk_chunks-startup_chunks,
                       active_heap_bytes=rounded+sdk_chunks))


class Returned(gdb.FinishBreakpoint):
    def __init__(self, kind, argument, owner):
        super().__init__(gdb.newest_frame(), internal=True)
        self.kind, self.argument, self.owner = kind, argument, owner

    def stop(self):
        try:
            if self.kind == 'sdk_allocations':
                # The prebuilt SDK allocator has no return-type debug info.
                pointer = integer('$rax')
                if not pointer or pointer in live_sdk:
                    raise RuntimeError('failed or duplicate SDK allocation')
                live_sdk[pointer] = (self.argument, chunk_size(pointer, self.argument), self.owner)
                sdk_events.append(dict(event='malloc', pointer=pointer,
                                       requested=self.argument,
                                       chunks=live_sdk[pointer][1], owner=self.owner,
                                       pc=integer('$pc')))
            elif integer('$eax') != 0:
                raise RuntimeError('protected allocator returned failure')
            counts[self.kind] += 1
            # A child pair is briefly unlinked during malloc/free. Walk the
            # buddy tree only at completed public allocator operations. In
            # these successful operations splitting increases live metadata
            # and coalescing decreases it; the stable returns capture peaks.
            if not protected or self.kind.startswith('protected_'):
                snapshot(self.kind)
            return False
        except Exception as exc:
            errors.append(str(exc))
            return True


class Entry(gdb.Breakpoint):
    def __init__(self, address, kind):
        super().__init__('*'+hex(address), internal=True)
        self.kind = kind

    def stop(self):
        try:
            argument = integer('$rdi')
            if self.kind == 'sdk_frees':
                # End logical lifetime at free entry; no freed-memory alias
                # or allocator return-type debug information is required.
                if argument:
                    if argument not in live_sdk:
                        raise RuntimeError('free of an unobserved SDK allocation')
                    del live_sdk[argument]
                    sdk_events.append(dict(event='free', pointer=argument))
                counts[self.kind] += 1
                if not protected:
                    snapshot(self.kind)
                return False
            owner = gdb.newest_frame().older().name() if self.kind == 'sdk_allocations' else None
            if protected and self.kind == 'sdk_allocations' and owner not in {'init_vrdl', 'allocate_node'}:
                raise RuntimeError('unclassified SDK allocation caller: '+str(owner))
            Returned(self.kind, argument, owner)
            return False
        except Exception as exc:
            errors.append(str(exc))
            return True


# Numeric enclave addresses avoid accidentally observing the host libc's malloc.
Entry(integer('$memory_malloc'), 'sdk_allocations')
Entry(integer('$memory_free'), 'sdk_frees')
if protected:
    Entry(integer('$memory_alloc'), 'protected_allocations')
    Entry(integer('$memory_release'), 'protected_frees')
snapshot('initial')


def report():
    print('MEMORY='+json.dumps(dict(events=events, counts=counts, errors=errors,
                                    sdk_events=sdk_events,
                                    static_root_bytes=node_size)))
