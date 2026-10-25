/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#pragma once

#include "silitra_types.h"

#ifdef __cplusplus
extern "C" {
#endif

silitra_err_t silitra_init(void);
silitra_err_t silitra_get_chip_info(silitra_chip_info_t *out);
silitra_err_t silitra_get_identity(silitra_identity_t *out);
silitra_err_t silitra_get_memory_info(silitra_memory_info_t *out);
silitra_err_t silitra_get_radio_info(silitra_radio_info_t *out);
silitra_err_t silitra_get_peripherals(silitra_peripheral_profile_t *out);
silitra_err_t silitra_get_manifest(silitra_manifest_t *out);
silitra_err_t silitra_get_fingerprint(silitra_fingerprint_kind_t kind, uint8_t out[32]);
silitra_err_t silitra_serialize_manifest(const silitra_manifest_t *manifest, uint8_t *out, size_t out_size, size_t *written);
silitra_err_t silitra_serialize_fingerprint_input(const silitra_manifest_t *manifest, silitra_fingerprint_kind_t kind, uint8_t *out, size_t out_size, size_t *written);

#ifdef __cplusplus
}
#endif
