/*
 * ENCBound restart - region descriptor model.
 *
 * A region is a disjoint, half-open interval of enclave-relative offsets with
 * a software ownership policy. Region membership is decided purely by address
 * arithmetic against this table; it is not a hardware property.
 */

#ifndef ENCBOUND_REGIONS_H
#define ENCBOUND_REGIONS_H

#include <stdint.h>

#define ENCBOUND_PLATFORM_CONFIG_MAX_REGIONS 32u

typedef enum encbound_region_policy {
    ENCBOUND_REGION_DENIED = 0,
    ENCBOUND_REGION_TRUSTED = 1,
    ENCBOUND_REGION_COMPAT = 2,
    ENCBOUND_REGION_PROTECTED = 3
} encbound_region_policy_t;

typedef enum encbound_region_domain {
    ENCBOUND_DOMAIN_NONE = 0,
    ENCBOUND_DOMAIN_HEAP = 1,
    ENCBOUND_DOMAIN_STACK = 2,
    ENCBOUND_DOMAIN_GLOBAL = 3
} encbound_region_domain_t;

typedef struct encbound_region {
    uint64_t start_offset; /* relative to the enclave base */
    uint64_t size;
    uint32_t policy;
    uint32_t domain;
} encbound_region_t;

typedef enum encbound_classify_result {
    ENCBOUND_CLASSIFY_INVALID = 0, /* crosses the enclave edge or bad args */
    ENCBOUND_CLASSIFY_OUTSIDE = 1, /* fully outside the enclave */
    ENCBOUND_CLASSIFY_REGION = 2   /* fully inside one region */
} encbound_classify_result_t;

#endif /* ENCBOUND_REGIONS_H */
