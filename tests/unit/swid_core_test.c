#include "swid.h"
#include <assert.h>
#include <string.h>

int main(void) {
    swid_manifest_t m, changed, invalid; uint8_t a[32], b[32], buf[4096], manifest_a[4096], manifest_b[4096], profile_a[4096], profile_b[4096], assembly_a[4096], assembly_b[4096], bounded_profile[SWID_FINGERPRINT_INPUT_MAX_BYTES]; size_t n = 0, na = 0, nb = 0;
    assert(swid_get_manifest(&m) == SWID_ERR_NOT_INITIALIZED);
    assert(swid_init() == SWID_OK);
    assert(swid_get_manifest(&m) == SWID_OK);
    assert(swid_serialize_manifest(&m, buf, sizeof(buf), &n) == SWID_OK && n > 8);
    assert(swid_get_fingerprint(SWID_FP_SILICON, a) == SWID_OK);
    for (int i = 0; i < 1000; ++i) { assert(swid_get_fingerprint(SWID_FP_SILICON, b) == SWID_OK); assert(memcmp(a, b, sizeof(a)) == 0); }
    m.identity.base_mac_valid = 1;
    m.identity.optional_uid_valid = 1;
    m.peripherals.count = 2;
    m.peripherals.items[0].type = SWID_PERIPH_UART;
    m.peripherals.items[0].supported = 1;
    m.peripherals.items[1].type = SWID_PERIPH_GPIO;
    m.peripherals.items[1].controller_count = 1;
    assert(swid_serialize_manifest(&m, manifest_a, sizeof(manifest_a), &na) == SWID_OK);
    changed = m;
    changed.peripherals.items[0] = m.peripherals.items[1];
    changed.peripherals.items[1] = m.peripherals.items[0];
    assert(swid_serialize_manifest(&changed, manifest_b, sizeof(manifest_b), &nb) == SWID_OK);
    assert(na == nb && memcmp(manifest_a, manifest_b, na) == 0);
    changed = m; changed.identity.base_mac[0] ^= 1u; changed.identity.optional_uid[0] ^= 1u;
    assert(swid_serialize_manifest(&changed, manifest_b, sizeof(manifest_b), &nb) == SWID_OK);
    assert(na == nb && memcmp(manifest_a, manifest_b, na) != 0);
    assert(swid_serialize_fingerprint_input(&m, SWID_FP_PROFILE, profile_a, sizeof(profile_a), &na) == SWID_OK);
    assert(swid_serialize_fingerprint_input(&changed, SWID_FP_PROFILE, profile_b, sizeof(profile_b), &nb) == SWID_OK);
    assert(na == nb && memcmp(profile_a, profile_b, na) == 0);
    changed = m; changed.memory.psram_capacity_bytes = 8u * 1024u * 1024u;
    for (int i = 0; i < 100; ++i) {
        assert(swid_serialize_fingerprint_input(&m, SWID_FP_PROFILE, profile_a, sizeof(profile_a), &na) == SWID_OK);
        assert(swid_serialize_fingerprint_input(&changed, SWID_FP_PROFILE, profile_b, sizeof(profile_b), &nb) == SWID_OK);
        assert(na != nb || memcmp(profile_a, profile_b, na) != 0);
    }
    assert(manifest_a[0] == 1 && manifest_a[3] == 'S' && manifest_a[4] == 'W' &&
           manifest_a[5] == 'I' && manifest_a[6] == 'D' && manifest_a[7] == 2 &&
           manifest_a[10] == SWID_MANIFEST_SCHEMA_VERSION);
    assert(swid_serialize_fingerprint_input(&m, SWID_FP_ASSEMBLY, assembly_a, sizeof(assembly_a), &na) == SWID_OK);
    changed = m; changed.memory.flash_unique_id ^= 1u; changed.memory.flash_unique_id_valid = 1;
    assert(swid_serialize_fingerprint_input(&changed, SWID_FP_ASSEMBLY, assembly_b, sizeof(assembly_b), &nb) == SWID_OK);
    assert(na != nb || memcmp(assembly_a, assembly_b, na) != 0);
    assert(swid_get_fingerprint((swid_fingerprint_kind_t)99, a) == SWID_ERR_ARG);
    assert(swid_serialize_manifest(&m, buf, 4, &n) == SWID_ERR_BUFFER);
    invalid = m; invalid.peripherals.count = SWID_MAX_PERIPHERALS + 1u;
    assert(swid_serialize_manifest(&invalid, buf, sizeof(buf), &n) == SWID_ERR_ARG);
    invalid = m; invalid.peripherals.count = 2;
    invalid.peripherals.items[0].type = SWID_PERIPH_UART;
    invalid.peripherals.items[1].type = SWID_PERIPH_UART;
    assert(swid_serialize_manifest(&invalid, buf, sizeof(buf), &n) == SWID_ERR_ARG);
    invalid.peripherals.items[1].type = (swid_peripheral_type_t)SWID_PERIPH_MAX;
    assert(swid_serialize_fingerprint_input(&invalid, SWID_FP_PROFILE, buf, sizeof(buf), &n) == SWID_ERR_ARG);
    invalid = m; invalid.peripherals.count = SWID_PERIPH_MAX;
    for (size_t i = 0; i < SWID_PERIPH_MAX; ++i) invalid.peripherals.items[i].type = (swid_peripheral_type_t)i;
    assert(swid_serialize_fingerprint_input(&invalid, SWID_FP_PROFILE, bounded_profile, sizeof(bounded_profile), &n) == SWID_OK);
    assert(n <= sizeof(bounded_profile));
    assert(swid_serialize_fingerprint_input(&invalid, SWID_FP_PROFILE, bounded_profile, n - 1u, &nb) == SWID_ERR_BUFFER);
    return 0;
}
