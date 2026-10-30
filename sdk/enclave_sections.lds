/*
 * ENCBound restart - application-owned COMPAT data section placement.
 *
 * Linked with -Wl,-T,enclave_sections.lds (an INSERT script that augments the
 * default linker layout). Application read-only tables that the instrumented
 * code accesses as untagged addresses are renamed into .encbound.appdata* and
 * collected here as one contiguous, read-only output section. The trusted
 * platform binding reads the __encbound_appdata_start/end symbols and carves
 * exactly this range out of the TRUSTED image region as COMPAT.
 *
 * Only app-owned objects are renamed into this section (the build does it per
 * object with objcopy); SDK/runtime rodata is never moved here, so the range is
 * not a mixed-section wholesale COMPAT classification.
 */
SECTIONS
{
    .encbound.appdata : ALIGN(4096)
    {
        __encbound_appdata_start = .;
        KEEP(*(.encbound.appdata))
        KEEP(*(.encbound.appdata.*))
        KEEP(*(.encbound.appdata.*.*))
        __encbound_appdata_end = .;
    }
}
INSERT AFTER .rodata;


/* Only explicitly opted-in, individually audited application objects may
 * supply these sections. Keep RO, RW and NOBITS on distinct pages. */
SECTIONS
{
    .encbound.apprw : ALIGN(4096)
    {
        __encbound_apprw_start = .;
        KEEP(*(.encbound.apprw.*))
        __encbound_apprw_end = .;
    }
    .encbound.appbss (NOLOAD) : ALIGN(4096)
    {
        __encbound_appbss_start = .;
        KEEP(*(.encbound.appbss.*))
        __encbound_appbss_end = .;
    }
}
INSERT AFTER .data;

SECTIONS
{
    .encbound.apprelro : ALIGN(4096)
    {
        __encbound_apprelro_start = .;
        KEEP(*(.encbound.apprelro.*))
        __encbound_apprelro_end = .;
        . = ALIGN(4096);
    }
}
INSERT AFTER .data.rel.ro;

/* Writable globals use per-object padded slots. Only compiler-generated
 * inputs enter these sections. Capability cells and initializer fixups remain
 * in the TRUSTED image gaps; they are never application-accessible. */
SECTIONS
{
    .encbound.globalrw : ALIGN(4096)
    {
        __encbound_globalrw_start = .;
        KEEP(*(.encbound.globalrw))
        __encbound_globalrw_end = .;
    }
    .encbound.globalbss (NOLOAD) : ALIGN(4096)
    {
        __encbound_globalbss_start = .;
        KEEP(*(.encbound.globalbss))
        __encbound_globalbss_end = .;
    }
    /* The pinned SDK rounds each LOAD's memory end to p_align when checking
     * segment overlap. Large protected globals can raise this BSS segment's
     * alignment above one page. Keep the following file-backed segment beyond
     * that rounded end; the gap is outside the application region symbols. */
    . = ALIGN(MAX(4096, ALIGNOF(.encbound.globalbss)));
    .encbound.gcaps : ALIGN(4096)
    {
        __encbound_gcaps_start = .;
        KEEP(*(encbound_gcaps))
        __encbound_gcaps_end = .;
    }
    .encbound.gfix : ALIGN(4096)
    {
        __encbound_gfix_start = .;
        KEEP(*(encbound_gfix))
        __encbound_gfix_end = .;
    }
}
INSERT AFTER .encbound.appbss;
