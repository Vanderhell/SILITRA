/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#pragma once
#include "silitra_types.h"

#define SILITRA_SHA256_INPUT_ALIGNMENT 4u
typedef struct {
    _Alignas(SILITRA_SHA256_INPUT_ALIGNMENT)
    uint8_t bytes[SILITRA_FINGERPRINT_INPUT_MAX_BYTES];
} silitra_sha256_input_buffer_t;
_Static_assert(_Alignof(silitra_sha256_input_buffer_t) >= SILITRA_SHA256_INPUT_ALIGNMENT,
               "SILITRA SHA-256 input storage must satisfy ESP ROM word alignment");

silitra_err_t silitra_port_collect(silitra_manifest_t *out);
/* data must be aligned to SILITRA_SHA256_INPUT_ALIGNMENT bytes. */
silitra_err_t silitra_port_hash256(const uint8_t *data, size_t len, uint8_t out[32]);
