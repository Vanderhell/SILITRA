#include "swid.h"
#include <assert.h>
#include <string.h>

int main(void) {
    swid_manifest_t m, changed; uint8_t a[32], b[32], buf[4096], profile_a[4096], profile_b[4096], assembly_a[4096], assembly_b[4096]; size_t n = 0, na = 0, nb = 0;
    assert(swid_get_manifest(&m) == SWID_ERR_NOT_INITIALIZED);
    assert(swid_init() == SWID_OK);
    assert(swid_get_manifest(&m) == SWID_OK);
    assert(swid_serialize_manifest(&m, buf, sizeof(buf), &n) == SWID_OK && n > 8);
    assert(swid_get_fingerprint(SWID_FP_SILICON, a) == SWID_OK);
    for (int i = 0; i < 1000; ++i) { assert(swid_get_fingerprint(SWID_FP_SILICON, b) == SWID_OK); assert(memcmp(a, b, sizeof(a)) == 0); }
    assert(swid_serialize_manifest(&m, profile_a, sizeof(profile_a), &na) == SWID_OK);
    changed = m; changed.identity.base_mac[0] ^= 1u; changed.identity.optional_uid[0] ^= 1u;
    assert(swid_serialize_manifest(&changed, profile_b, sizeof(profile_b), &nb) == SWID_OK);
    assert(na == nb && memcmp(profile_a, profile_b, na) == 0);
    assert(swid_serialize_fingerprint_input(&m, SWID_FP_ASSEMBLY, assembly_a, sizeof(assembly_a), &na) == SWID_OK);
    changed = m; changed.memory.flash_unique_id ^= 1u; changed.memory.flash_unique_id_valid = 1;
    assert(swid_serialize_fingerprint_input(&changed, SWID_FP_ASSEMBLY, assembly_b, sizeof(assembly_b), &nb) == SWID_OK);
    assert(na != nb || memcmp(assembly_a, assembly_b, na) != 0);
    assert(swid_get_fingerprint((swid_fingerprint_kind_t)99, a) == SWID_ERR_ARG);
    assert(swid_serialize_manifest(&m, buf, 4, &n) == SWID_ERR_BUFFER);
    return 0;
}
