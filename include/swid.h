#pragma once

#include "swid_types.h"

#ifdef __cplusplus
extern "C" {
#endif

swid_err_t swid_init(void);
swid_err_t swid_get_chip_info(swid_chip_info_t *out);
swid_err_t swid_get_identity(swid_identity_t *out);
swid_err_t swid_get_memory_info(swid_memory_info_t *out);
swid_err_t swid_get_radio_info(swid_radio_info_t *out);
swid_err_t swid_get_peripherals(swid_peripheral_profile_t *out);
swid_err_t swid_get_manifest(swid_manifest_t *out);
swid_err_t swid_get_fingerprint(swid_fingerprint_kind_t kind, uint8_t out[32]);
swid_err_t swid_serialize_manifest(const swid_manifest_t *manifest, uint8_t *out, size_t out_size, size_t *written);
swid_err_t swid_serialize_fingerprint_input(const swid_manifest_t *manifest, swid_fingerprint_kind_t kind, uint8_t *out, size_t out_size, size_t *written);

#ifdef __cplusplus
}
#endif
