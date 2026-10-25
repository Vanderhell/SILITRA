/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "silitra.h"
#include "swid.h"
#include "../ports/silitra_port.h"

#include <string.h>

static silitra_manifest_t g_manifest;
static uint8_t g_initialized;

static silitra_err_t append_bytes(uint8_t *out, size_t cap, size_t *pos, uint8_t type, const void *data, size_t len) {
    if (!out || !pos || (!data && len) || len > 0xFFFFu || *pos > cap || cap - *pos < len + 3u) return SILITRA_ERR_BUFFER;
    out[(*pos)++] = type; out[(*pos)++] = (uint8_t)(len & 0xFFu); out[(*pos)++] = (uint8_t)(len >> 8);
    if (len) {
        memcpy(out + *pos, data, len);
    }
    *pos += len;
    return SILITRA_OK;
}

static silitra_err_t append_u32(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint32_t value) {
    uint8_t b[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    return append_bytes(out, cap, pos, type, b, sizeof(b));
}

static silitra_err_t append_u64(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint64_t value) {
    uint8_t b[8];
    for (unsigned i = 0; i < sizeof(b); ++i) b[i] = (uint8_t)(value >> (8u * i));
    return append_bytes(out, cap, pos, type, b, sizeof(b));
}

static silitra_err_t append_u16(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint16_t value) {
    uint8_t b[2] = {(uint8_t)value, (uint8_t)(value >> 8)};
    return append_bytes(out, cap, pos, type, b, sizeof(b));
}

static silitra_err_t append_u8(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint8_t value) {
    return append_bytes(out, cap, pos, type, &value, sizeof(value));
}

static silitra_err_t validate_manifest(const silitra_manifest_t *m) {
    if (!m || m->peripherals.count > SILITRA_MAX_PERIPHERALS) return SILITRA_ERR_ARG;
    uint64_t seen = 0;
    for (size_t i = 0; i < m->peripherals.count; ++i) {
        const int type = (int)m->peripherals.items[i].type;
        if (type < 0 || type >= SILITRA_PERIPH_MAX) return SILITRA_ERR_ARG;
        const uint64_t bit = UINT64_C(1) << (unsigned)type;
        if (seen & bit) return SILITRA_ERR_ARG;
        seen |= bit;
    }
    return SILITRA_OK;
}

static silitra_err_t serialize_kind(const silitra_manifest_t *m, silitra_fingerprint_kind_t kind, uint8_t *out, size_t cap, size_t *written) {
    size_t p = 0; const uint8_t magic[4] = {'S','W','I','D'};
    if (!m || !out || !written) return SILITRA_ERR_ARG;
    if (validate_manifest(m) != SILITRA_OK) return SILITRA_ERR_ARG;
    *written = 0;
    if (append_bytes(out, cap, &p, 1, magic, sizeof(magic)) != SILITRA_OK || append_u32(out, cap, &p, 2, SILITRA_SCHEMA_VERSION) != SILITRA_OK || append_u8(out, cap, &p, 3, (uint8_t)kind) != SILITRA_OK) return SILITRA_ERR_BUFFER;
    if (append_u16(out, cap, &p, 10, m->chip.family) != SILITRA_OK || append_u16(out, cap, &p, 11, m->chip.model) != SILITRA_OK || append_u8(out, cap, &p, 12, m->chip.revision) != SILITRA_OK || append_u8(out, cap, &p, 13, m->chip.cores) != SILITRA_OK || append_u8(out, cap, &p, 14, m->chip.package) != SILITRA_OK || append_u32(out, cap, &p, 15, m->chip.features) != SILITRA_OK) return SILITRA_ERR_BUFFER;
    if (kind == SILITRA_FP_SILICON || kind == SILITRA_FP_ASSEMBLY) {
        if (append_bytes(out, cap, &p, 20, m->identity.base_mac_valid ? m->identity.base_mac : NULL, m->identity.base_mac_valid ? sizeof(m->identity.base_mac) : 0) != SILITRA_OK || append_bytes(out, cap, &p, 21, m->identity.optional_uid_valid ? m->identity.optional_uid : NULL, m->identity.optional_uid_valid ? sizeof(m->identity.optional_uid) : 0) != SILITRA_OK) return SILITRA_ERR_BUFFER;
    }
    if (kind == SILITRA_FP_ASSEMBLY || kind == SILITRA_FP_PROFILE) {
        if (append_u32(out, cap, &p, 30, m->memory.flash_jedec_id) != SILITRA_OK || append_u32(out, cap, &p, 31, m->memory.flash_capacity_bytes) != SILITRA_OK || append_u32(out, cap, &p, 32, m->memory.psram_capacity_bytes) != SILITRA_OK || append_u8(out, cap, &p, 33, m->memory.psram_present) != SILITRA_OK || append_u8(out, cap, &p, 34, m->memory.psram_interface) != SILITRA_OK || append_u8(out, cap, &p, 35, m->memory.psram_location) != SILITRA_OK) return SILITRA_ERR_BUFFER;
    }
    if (kind == SILITRA_FP_ASSEMBLY) {
        if (append_bytes(out, cap, &p, 36, m->memory.flash_unique_id_valid ? &m->memory.flash_unique_id : NULL, m->memory.flash_unique_id_valid ? sizeof(m->memory.flash_unique_id) : 0) != SILITRA_OK) return SILITRA_ERR_BUFFER;
    }
    if (kind == SILITRA_FP_PROFILE) {
        if (append_u8(out, cap, &p, 40, m->radio.wifi_supported) != SILITRA_OK || append_u8(out, cap, &p, 41, m->radio.wifi_generation) != SILITRA_OK || append_u8(out, cap, &p, 42, m->radio.bluetooth_supported) != SILITRA_OK || append_u8(out, cap, &p, 43, m->radio.ble_supported) != SILITRA_OK || append_u8(out, cap, &p, 44, m->radio.bt_classic_supported) != SILITRA_OK) return SILITRA_ERR_BUFFER;
        for (uint32_t type = 0; type < SILITRA_PERIPH_MAX; ++type) {
            for (size_t i = 0; i < m->peripherals.count; ++i) {
                const silitra_peripheral_t *item = &m->peripherals.items[i];
                if ((uint32_t)item->type != type) continue;
                uint8_t encoded[12] = {(uint8_t)item->type, item->supported, item->controller_count, (uint8_t)item->channel_count, (uint8_t)(item->channel_count >> 8), (uint8_t)item->status, (uint8_t)item->evidence, (uint8_t)item->feature_flags, (uint8_t)(item->feature_flags >> 8), (uint8_t)(item->feature_flags >> 16), (uint8_t)(item->feature_flags >> 24), 0};
                if (append_bytes(out, cap, &p, 50, encoded, sizeof(encoded)) != SILITRA_OK) return SILITRA_ERR_BUFFER;
            }
        }
    }
    *written = p; return SILITRA_OK;
}

silitra_err_t silitra_init(void) {
    silitra_manifest_t fresh; memset(&fresh, 0, sizeof(fresh));
    silitra_err_t err = silitra_port_collect(&fresh); if (err != SILITRA_OK) return err;
    g_manifest = fresh; g_initialized = 1; return SILITRA_OK;
}

#define GETTER(name, field, type) \
silitra_err_t name(type *out) { if (!out) return SILITRA_ERR_ARG; if (!g_initialized) return SILITRA_ERR_NOT_INITIALIZED; *out = g_manifest.field; return SILITRA_OK; }
GETTER(silitra_get_chip_info, chip, silitra_chip_info_t)
GETTER(silitra_get_identity, identity, silitra_identity_t)
GETTER(silitra_get_memory_info, memory, silitra_memory_info_t)
GETTER(silitra_get_radio_info, radio, silitra_radio_info_t)
GETTER(silitra_get_peripherals, peripherals, silitra_peripheral_profile_t)
#undef GETTER

silitra_err_t silitra_get_manifest(silitra_manifest_t *out) { if (!out) return SILITRA_ERR_ARG; if (!g_initialized) return SILITRA_ERR_NOT_INITIALIZED; *out = g_manifest; return SILITRA_OK; }

silitra_err_t silitra_serialize_manifest(const silitra_manifest_t *manifest, uint8_t *out, size_t out_size, size_t *written) {
    if (!manifest || !out || !written) return SILITRA_ERR_ARG;
    if (validate_manifest(manifest) != SILITRA_OK) return SILITRA_ERR_ARG;
    *written = 0;
    size_t p = 0;
    const uint8_t magic[4] = {'S','W','I','D'};
    if (append_bytes(out, out_size, &p, 1, magic, sizeof(magic)) != SILITRA_OK ||
        append_u32(out, out_size, &p, 2, SILITRA_MANIFEST_SCHEMA_VERSION) != SILITRA_OK) return SILITRA_ERR_BUFFER;

    const silitra_chip_info_t *c = &manifest->chip;
    if (append_u16(out, out_size, &p, 10, c->family) != SILITRA_OK ||
        append_u16(out, out_size, &p, 11, c->model) != SILITRA_OK ||
        append_u8(out, out_size, &p, 12, c->revision) != SILITRA_OK ||
        append_u8(out, out_size, &p, 13, c->cores) != SILITRA_OK ||
        append_u8(out, out_size, &p, 14, c->package) != SILITRA_OK ||
        append_u32(out, out_size, &p, 15, c->features) != SILITRA_OK ||
        append_u8(out, out_size, &p, 16, (uint8_t)c->status) != SILITRA_OK ||
        append_u8(out, out_size, &p, 17, (uint8_t)c->evidence) != SILITRA_OK) return SILITRA_ERR_BUFFER;

    const silitra_identity_t *id = &manifest->identity;
    if (append_bytes(out, out_size, &p, 20, id->base_mac_valid ? id->base_mac : NULL,
                     id->base_mac_valid ? sizeof(id->base_mac) : 0) != SILITRA_OK ||
        append_bytes(out, out_size, &p, 21, id->optional_uid_valid ? id->optional_uid : NULL,
                     id->optional_uid_valid ? sizeof(id->optional_uid) : 0) != SILITRA_OK ||
        append_u8(out, out_size, &p, 22, id->optional_uid_bits) != SILITRA_OK ||
        append_u8(out, out_size, &p, 23, id->factory_calibration_present) != SILITRA_OK ||
        append_u8(out, out_size, &p, 24, (uint8_t)id->status) != SILITRA_OK ||
        append_u8(out, out_size, &p, 25, (uint8_t)id->evidence) != SILITRA_OK) return SILITRA_ERR_BUFFER;

    const silitra_memory_info_t *mem = &manifest->memory;
    if (append_u32(out, out_size, &p, 30, mem->flash_jedec_id) != SILITRA_OK ||
        append_u32(out, out_size, &p, 31, mem->flash_capacity_bytes) != SILITRA_OK ||
        append_u64(out, out_size, &p, 32, mem->flash_unique_id_valid ? mem->flash_unique_id : 0) != SILITRA_OK ||
        append_u8(out, out_size, &p, 33, mem->flash_unique_id_valid) != SILITRA_OK ||
        append_u8(out, out_size, &p, 34, mem->flash_mode) != SILITRA_OK ||
        append_u8(out, out_size, &p, 35, mem->flash_manufacturer) != SILITRA_OK ||
        append_u8(out, out_size, &p, 36, mem->flash_type) != SILITRA_OK ||
        append_u8(out, out_size, &p, 37, mem->flash_capacity_code) != SILITRA_OK ||
        append_u32(out, out_size, &p, 38, mem->psram_capacity_bytes) != SILITRA_OK ||
        append_u8(out, out_size, &p, 39, mem->psram_present) != SILITRA_OK ||
        append_u8(out, out_size, &p, 40, mem->psram_interface) != SILITRA_OK ||
        append_u8(out, out_size, &p, 41, mem->psram_manufacturer) != SILITRA_OK ||
        append_u8(out, out_size, &p, 42, mem->psram_location) != SILITRA_OK ||
        append_u8(out, out_size, &p, 43, (uint8_t)mem->status) != SILITRA_OK ||
        append_u8(out, out_size, &p, 44, (uint8_t)mem->evidence) != SILITRA_OK)
        return SILITRA_ERR_BUFFER;

    const silitra_radio_info_t *r = &manifest->radio;
    if (append_u8(out, out_size, &p, 50, r->wifi_supported) != SILITRA_OK ||
        append_u8(out, out_size, &p, 51, r->wifi_generation) != SILITRA_OK ||
        append_u8(out, out_size, &p, 52, r->bluetooth_supported) != SILITRA_OK ||
        append_u8(out, out_size, &p, 53, r->ble_supported) != SILITRA_OK ||
        append_u8(out, out_size, &p, 54, r->bt_classic_supported) != SILITRA_OK ||
        append_bytes(out, out_size, &p, 55, r->sta_mac, sizeof(r->sta_mac)) != SILITRA_OK ||
        append_bytes(out, out_size, &p, 56, r->ap_mac, sizeof(r->ap_mac)) != SILITRA_OK ||
        append_bytes(out, out_size, &p, 57, r->bt_mac, sizeof(r->bt_mac)) != SILITRA_OK ||
        append_u8(out, out_size, &p, 58, r->derived_mac_count) != SILITRA_OK ||
        append_u8(out, out_size, &p, 59, r->rf_calibration_present) != SILITRA_OK ||
        append_u8(out, out_size, &p, 60, (uint8_t)r->status) != SILITRA_OK ||
        append_u8(out, out_size, &p, 61, (uint8_t)r->evidence) != SILITRA_OK) return SILITRA_ERR_BUFFER;

    if (append_u8(out, out_size, &p, 70, (uint8_t)manifest->peripherals.status) != SILITRA_OK ||
        append_u8(out, out_size, &p, 71, (uint8_t)manifest->peripherals.evidence) != SILITRA_OK) return SILITRA_ERR_BUFFER;
    for (uint32_t type = 0; type < SILITRA_PERIPH_MAX; ++type) {
        for (size_t i = 0; i < manifest->peripherals.count; ++i) {
            const silitra_peripheral_t *item = &manifest->peripherals.items[i];
            if ((uint32_t)item->type != type) continue;
            uint8_t encoded[11] = {(uint8_t)item->type, item->supported, item->controller_count,
                (uint8_t)item->channel_count, (uint8_t)(item->channel_count >> 8),
                (uint8_t)item->status, (uint8_t)item->evidence,
                (uint8_t)item->feature_flags, (uint8_t)(item->feature_flags >> 8),
                (uint8_t)(item->feature_flags >> 16), (uint8_t)(item->feature_flags >> 24)};
            if (append_bytes(out, out_size, &p, 80, encoded, sizeof(encoded)) != SILITRA_OK) return SILITRA_ERR_BUFFER;
        }
    }
    *written = p;
    return SILITRA_OK;
}

silitra_err_t silitra_serialize_fingerprint_input(const silitra_manifest_t *manifest, silitra_fingerprint_kind_t kind, uint8_t *out, size_t out_size, size_t *written) {
    if (kind < SILITRA_FP_SILICON || kind > SILITRA_FP_PROFILE) return SILITRA_ERR_ARG;
    return serialize_kind(manifest, kind, out, out_size, written);
}

/* Real legacy ABI symbols: aliases alone would only provide source compatibility. */
swid_err_t swid_init(void) { return silitra_init(); }
swid_err_t swid_get_chip_info(swid_chip_info_t *out) { return silitra_get_chip_info(out); }
swid_err_t swid_get_identity(swid_identity_t *out) { return silitra_get_identity(out); }
swid_err_t swid_get_memory_info(swid_memory_info_t *out) { return silitra_get_memory_info(out); }
swid_err_t swid_get_radio_info(swid_radio_info_t *out) { return silitra_get_radio_info(out); }
swid_err_t swid_get_peripherals(swid_peripheral_profile_t *out) { return silitra_get_peripherals(out); }
swid_err_t swid_get_manifest(swid_manifest_t *out) { return silitra_get_manifest(out); }
swid_err_t swid_get_fingerprint(swid_fingerprint_kind_t kind, uint8_t out[32]) { return silitra_get_fingerprint((silitra_fingerprint_kind_t)kind, out); }
swid_err_t swid_serialize_manifest(const swid_manifest_t *m, uint8_t *out, size_t n, size_t *written) { return silitra_serialize_manifest(m, out, n, written); }
swid_err_t swid_serialize_fingerprint_input(const swid_manifest_t *m, swid_fingerprint_kind_t kind, uint8_t *out, size_t n, size_t *written) { return silitra_serialize_fingerprint_input(m, (silitra_fingerprint_kind_t)kind, out, n, written); }

silitra_err_t silitra_get_fingerprint(silitra_fingerprint_kind_t kind, uint8_t out[32]) {
    /* Keep the serialized input word-aligned without shared mutable storage. */
    _Alignas(4) uint8_t canonical[SILITRA_FINGERPRINT_INPUT_MAX_BYTES]; size_t written = 0; if (!out) return SILITRA_ERR_ARG; if (!g_initialized) return SILITRA_ERR_NOT_INITIALIZED;
    if (kind < SILITRA_FP_SILICON || kind > SILITRA_FP_PROFILE) return SILITRA_ERR_ARG;
    silitra_err_t err = serialize_kind(&g_manifest, kind, canonical, sizeof(canonical), &written); if (err != SILITRA_OK) return err;
    return silitra_port_hash256(canonical, written, out);
}
