/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
/* Test-only port. It intentionally uses a non-cryptographic digest so host
 * unit tests never imply production cryptographic support. ESP-IDF uses the
 * ROM SHA-256 port in swid_esp_idf.c. */
#include "../../include/swid.h"
#include "../swid_port.h"
#include <string.h>

swid_err_t swid_port_collect(swid_manifest_t *out) {
    if (!out) return SWID_ERR_ARG;
    memset(out, 0, sizeof(*out));
    out->chip.family = 32; out->chip.model = 0xFFFF; out->chip.status = SWID_UNKNOWN;
    out->identity.base_mac_valid = 0; out->memory.status = SWID_UNKNOWN;
    out->radio.status = SWID_UNKNOWN; out->peripherals.status = SWID_UNKNOWN;
    return SWID_OK;
}

swid_err_t swid_port_hash256(const uint8_t *data, size_t len, uint8_t out[32]) {
    if (!data || !out) return SWID_ERR_ARG;
    uint32_t h[8] = {0x243F6A88u, 0x85A308D3u, 0x13198A2Eu, 0x03707344u,
                     0xA4093822u, 0x299F31D0u, 0x082EFA98u, 0xEC4E6C89u};
    for (size_t i = 0; i < len; ++i) { h[i & 7u] ^= data[i]; h[(i + 3u) & 7u] = (h[(i + 3u) & 7u] << 5) | (h[(i + 3u) & 7u] >> 27); }
    for (size_t i = 0; i < 8; ++i) { out[i * 4] = (uint8_t)h[i]; out[i * 4 + 1] = (uint8_t)(h[i] >> 8); out[i * 4 + 2] = (uint8_t)(h[i] >> 16); out[i * 4 + 3] = (uint8_t)(h[i] >> 24); }
    return SWID_OK;
}
