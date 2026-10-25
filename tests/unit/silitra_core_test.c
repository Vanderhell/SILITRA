/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "silitra.h"
#include "swid.h"
#include <assert.h>
#include <string.h>

int main(void) {
    silitra_manifest_t m, changed, invalid; uint8_t a[32], b[32], buf[4096], manifest_a[4096], manifest_b[4096], profile_a[4096], profile_b[4096], assembly_a[4096], assembly_b[4096], bounded_profile[SILITRA_FINGERPRINT_INPUT_MAX_BYTES]; size_t n = 0, na = 0, nb = 0;
    assert(silitra_get_manifest(&m) == SILITRA_ERR_NOT_INITIALIZED);
    assert(silitra_init() == SILITRA_OK);
    assert(silitra_get_manifest(&m) == SILITRA_OK);
    swid_manifest_t legacy_manifest;
    assert(swid_get_manifest(&legacy_manifest) == SWID_OK);
    assert(sizeof(legacy_manifest) == sizeof(m));
    assert(silitra_serialize_manifest(&m, buf, sizeof(buf), &n) == SILITRA_OK && n > 8);
    uint8_t legacy_buf[4096]; size_t legacy_n = 0;
    assert(swid_serialize_manifest(&m, legacy_buf, sizeof(legacy_buf), &legacy_n) == SWID_OK);
    assert(n == legacy_n && memcmp(buf, legacy_buf, n) == 0);
    assert(silitra_get_fingerprint(SILITRA_FP_SILICON, a) == SILITRA_OK);
    assert(swid_get_fingerprint(SWID_FP_SILICON, b) == SWID_OK);
    assert(memcmp(a, b, sizeof(a)) == 0);
    for (int i = 0; i < 1000; ++i) { assert(silitra_get_fingerprint(SILITRA_FP_SILICON, b) == SILITRA_OK); assert(memcmp(a, b, sizeof(a)) == 0); }
    m.identity.base_mac_valid = 1;
    m.identity.optional_uid_valid = 1;
    m.peripherals.count = 2;
    m.peripherals.items[0].type = SILITRA_PERIPH_UART;
    m.peripherals.items[0].supported = 1;
    m.peripherals.items[1].type = SILITRA_PERIPH_GPIO;
    m.peripherals.items[1].controller_count = 1;
    assert(silitra_serialize_manifest(&m, manifest_a, sizeof(manifest_a), &na) == SILITRA_OK);
    changed = m;
    changed.peripherals.items[0] = m.peripherals.items[1];
    changed.peripherals.items[1] = m.peripherals.items[0];
    assert(silitra_serialize_manifest(&changed, manifest_b, sizeof(manifest_b), &nb) == SILITRA_OK);
    assert(na == nb && memcmp(manifest_a, manifest_b, na) == 0);
    changed = m; changed.identity.base_mac[0] ^= 1u; changed.identity.optional_uid[0] ^= 1u;
    assert(silitra_serialize_manifest(&changed, manifest_b, sizeof(manifest_b), &nb) == SILITRA_OK);
    assert(na == nb && memcmp(manifest_a, manifest_b, na) != 0);
    assert(silitra_serialize_fingerprint_input(&m, SILITRA_FP_PROFILE, profile_a, sizeof(profile_a), &na) == SILITRA_OK);
    assert(silitra_serialize_fingerprint_input(&changed, SILITRA_FP_PROFILE, profile_b, sizeof(profile_b), &nb) == SILITRA_OK);
    assert(na == nb && memcmp(profile_a, profile_b, na) == 0);
    changed = m; changed.memory.psram_capacity_bytes = 8u * 1024u * 1024u;
    for (int i = 0; i < 100; ++i) {
        assert(silitra_serialize_fingerprint_input(&m, SILITRA_FP_PROFILE, profile_a, sizeof(profile_a), &na) == SILITRA_OK);
        assert(silitra_serialize_fingerprint_input(&changed, SILITRA_FP_PROFILE, profile_b, sizeof(profile_b), &nb) == SILITRA_OK);
        assert(na != nb || memcmp(profile_a, profile_b, na) != 0);
    }
    assert(manifest_a[0] == 1 && manifest_a[3] == 'S' && manifest_a[4] == 'W' &&
           manifest_a[5] == 'I' && manifest_a[6] == 'D' && manifest_a[7] == 2 &&
           manifest_a[10] == SILITRA_MANIFEST_SCHEMA_VERSION);
    assert(silitra_serialize_fingerprint_input(&m, SILITRA_FP_ASSEMBLY, assembly_a, sizeof(assembly_a), &na) == SILITRA_OK);
    changed = m; changed.memory.flash_unique_id ^= 1u; changed.memory.flash_unique_id_valid = 1;
    assert(silitra_serialize_fingerprint_input(&changed, SILITRA_FP_ASSEMBLY, assembly_b, sizeof(assembly_b), &nb) == SILITRA_OK);
    assert(na != nb || memcmp(assembly_a, assembly_b, na) != 0);
    assert(silitra_get_fingerprint((silitra_fingerprint_kind_t)99, a) == SILITRA_ERR_ARG);
    assert(silitra_serialize_manifest(&m, buf, 4, &n) == SILITRA_ERR_BUFFER);
    invalid = m; invalid.peripherals.count = SILITRA_MAX_PERIPHERALS + 1u;
    assert(silitra_serialize_manifest(&invalid, buf, sizeof(buf), &n) == SILITRA_ERR_ARG);
    invalid = m; invalid.peripherals.count = 2;
    invalid.peripherals.items[0].type = SILITRA_PERIPH_UART;
    invalid.peripherals.items[1].type = SILITRA_PERIPH_UART;
    assert(silitra_serialize_manifest(&invalid, buf, sizeof(buf), &n) == SILITRA_ERR_ARG);
    invalid.peripherals.items[1].type = (silitra_peripheral_type_t)SILITRA_PERIPH_MAX;
    assert(silitra_serialize_fingerprint_input(&invalid, SILITRA_FP_PROFILE, buf, sizeof(buf), &n) == SILITRA_ERR_ARG);
    invalid = m; invalid.peripherals.count = SILITRA_PERIPH_MAX;
    for (size_t i = 0; i < SILITRA_PERIPH_MAX; ++i) invalid.peripherals.items[i].type = (silitra_peripheral_type_t)i;
    assert(silitra_serialize_fingerprint_input(&invalid, SILITRA_FP_PROFILE, bounded_profile, sizeof(bounded_profile), &n) == SILITRA_OK);
    assert(n <= sizeof(bounded_profile));
    assert(silitra_serialize_fingerprint_input(&invalid, SILITRA_FP_PROFILE, bounded_profile, n - 1u, &nb) == SILITRA_ERR_BUFFER);
    return 0;
}
