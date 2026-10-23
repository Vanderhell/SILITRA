#include "swid.h"
#include "../ports/swid_port.h"

#include <string.h>

static swid_manifest_t g_manifest;
static uint8_t g_initialized;

static swid_err_t append_bytes(uint8_t *out, size_t cap, size_t *pos, uint8_t type, const void *data, size_t len) {
    if (!out || !pos || (!data && len) || len > 0xFFFFu || *pos > cap || cap - *pos < len + 3u) return SWID_ERR_BUFFER;
    out[(*pos)++] = type; out[(*pos)++] = (uint8_t)(len & 0xFFu); out[(*pos)++] = (uint8_t)(len >> 8);
    if (len) {
        memcpy(out + *pos, data, len);
    }
    *pos += len;
    return SWID_OK;
}

static swid_err_t append_u32(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint32_t value) {
    uint8_t b[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    return append_bytes(out, cap, pos, type, b, sizeof(b));
}

static swid_err_t append_u64(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint64_t value) {
    uint8_t b[8];
    for (unsigned i = 0; i < sizeof(b); ++i) b[i] = (uint8_t)(value >> (8u * i));
    return append_bytes(out, cap, pos, type, b, sizeof(b));
}

static swid_err_t append_u16(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint16_t value) {
    uint8_t b[2] = {(uint8_t)value, (uint8_t)(value >> 8)};
    return append_bytes(out, cap, pos, type, b, sizeof(b));
}

static swid_err_t append_u8(uint8_t *out, size_t cap, size_t *pos, uint8_t type, uint8_t value) {
    return append_bytes(out, cap, pos, type, &value, sizeof(value));
}

static swid_err_t validate_manifest(const swid_manifest_t *m) {
    if (!m || m->peripherals.count > SWID_MAX_PERIPHERALS) return SWID_ERR_ARG;
    uint64_t seen = 0;
    for (size_t i = 0; i < m->peripherals.count; ++i) {
        const int type = (int)m->peripherals.items[i].type;
        if (type < 0 || type >= SWID_PERIPH_MAX) return SWID_ERR_ARG;
        const uint64_t bit = UINT64_C(1) << (unsigned)type;
        if (seen & bit) return SWID_ERR_ARG;
        seen |= bit;
    }
    return SWID_OK;
}

static swid_err_t serialize_kind(const swid_manifest_t *m, swid_fingerprint_kind_t kind, uint8_t *out, size_t cap, size_t *written) {
    size_t p = 0; const uint8_t magic[4] = {'S','W','I','D'};
    if (!m || !out || !written) return SWID_ERR_ARG;
    if (validate_manifest(m) != SWID_OK) return SWID_ERR_ARG;
    *written = 0;
    if (append_bytes(out, cap, &p, 1, magic, sizeof(magic)) != SWID_OK || append_u32(out, cap, &p, 2, SWID_SCHEMA_VERSION) != SWID_OK || append_u8(out, cap, &p, 3, (uint8_t)kind) != SWID_OK) return SWID_ERR_BUFFER;
    if (append_u16(out, cap, &p, 10, m->chip.family) != SWID_OK || append_u16(out, cap, &p, 11, m->chip.model) != SWID_OK || append_u8(out, cap, &p, 12, m->chip.revision) != SWID_OK || append_u8(out, cap, &p, 13, m->chip.cores) != SWID_OK || append_u8(out, cap, &p, 14, m->chip.package) != SWID_OK || append_u32(out, cap, &p, 15, m->chip.features) != SWID_OK) return SWID_ERR_BUFFER;
    if (kind == SWID_FP_SILICON || kind == SWID_FP_ASSEMBLY) {
        if (append_bytes(out, cap, &p, 20, m->identity.base_mac_valid ? m->identity.base_mac : NULL, m->identity.base_mac_valid ? sizeof(m->identity.base_mac) : 0) != SWID_OK || append_bytes(out, cap, &p, 21, m->identity.optional_uid_valid ? m->identity.optional_uid : NULL, m->identity.optional_uid_valid ? sizeof(m->identity.optional_uid) : 0) != SWID_OK) return SWID_ERR_BUFFER;
    }
    if (kind == SWID_FP_ASSEMBLY || kind == SWID_FP_PROFILE) {
        if (append_u32(out, cap, &p, 30, m->memory.flash_jedec_id) != SWID_OK || append_u32(out, cap, &p, 31, m->memory.flash_capacity_bytes) != SWID_OK || append_u32(out, cap, &p, 32, m->memory.psram_capacity_bytes) != SWID_OK || append_u8(out, cap, &p, 33, m->memory.psram_present) != SWID_OK || append_u8(out, cap, &p, 34, m->memory.psram_interface) != SWID_OK || append_u8(out, cap, &p, 35, m->memory.psram_location) != SWID_OK) return SWID_ERR_BUFFER;
    }
    if (kind == SWID_FP_ASSEMBLY) {
        if (append_bytes(out, cap, &p, 36, m->memory.flash_unique_id_valid ? &m->memory.flash_unique_id : NULL, m->memory.flash_unique_id_valid ? sizeof(m->memory.flash_unique_id) : 0) != SWID_OK) return SWID_ERR_BUFFER;
    }
    if (kind == SWID_FP_PROFILE) {
        if (append_u8(out, cap, &p, 40, m->radio.wifi_supported) != SWID_OK || append_u8(out, cap, &p, 41, m->radio.wifi_generation) != SWID_OK || append_u8(out, cap, &p, 42, m->radio.bluetooth_supported) != SWID_OK || append_u8(out, cap, &p, 43, m->radio.ble_supported) != SWID_OK || append_u8(out, cap, &p, 44, m->radio.bt_classic_supported) != SWID_OK) return SWID_ERR_BUFFER;
        for (uint32_t type = 0; type < SWID_PERIPH_MAX; ++type) {
            for (size_t i = 0; i < m->peripherals.count; ++i) {
                const swid_peripheral_t *item = &m->peripherals.items[i];
                if ((uint32_t)item->type != type) continue;
                uint8_t encoded[12] = {(uint8_t)item->type, item->supported, item->controller_count, (uint8_t)item->channel_count, (uint8_t)(item->channel_count >> 8), (uint8_t)item->status, (uint8_t)item->evidence, (uint8_t)item->feature_flags, (uint8_t)(item->feature_flags >> 8), (uint8_t)(item->feature_flags >> 16), (uint8_t)(item->feature_flags >> 24), 0};
                if (append_bytes(out, cap, &p, 50, encoded, sizeof(encoded)) != SWID_OK) return SWID_ERR_BUFFER;
            }
        }
    }
    *written = p; return SWID_OK;
}

swid_err_t swid_init(void) {
    swid_manifest_t fresh; memset(&fresh, 0, sizeof(fresh));
    swid_err_t err = swid_port_collect(&fresh); if (err != SWID_OK) return err;
    g_manifest = fresh; g_initialized = 1; return SWID_OK;
}

#define GETTER(name, field, type) \
swid_err_t name(type *out) { if (!out) return SWID_ERR_ARG; if (!g_initialized) return SWID_ERR_NOT_INITIALIZED; *out = g_manifest.field; return SWID_OK; }
GETTER(swid_get_chip_info, chip, swid_chip_info_t)
GETTER(swid_get_identity, identity, swid_identity_t)
GETTER(swid_get_memory_info, memory, swid_memory_info_t)
GETTER(swid_get_radio_info, radio, swid_radio_info_t)
GETTER(swid_get_peripherals, peripherals, swid_peripheral_profile_t)
#undef GETTER

swid_err_t swid_get_manifest(swid_manifest_t *out) { if (!out) return SWID_ERR_ARG; if (!g_initialized) return SWID_ERR_NOT_INITIALIZED; *out = g_manifest; return SWID_OK; }

swid_err_t swid_serialize_manifest(const swid_manifest_t *manifest, uint8_t *out, size_t out_size, size_t *written) {
    if (!manifest || !out || !written) return SWID_ERR_ARG;
    if (validate_manifest(manifest) != SWID_OK) return SWID_ERR_ARG;
    *written = 0;
    size_t p = 0;
    const uint8_t magic[4] = {'S','W','I','D'};
    if (append_bytes(out, out_size, &p, 1, magic, sizeof(magic)) != SWID_OK ||
        append_u32(out, out_size, &p, 2, SWID_MANIFEST_SCHEMA_VERSION) != SWID_OK) return SWID_ERR_BUFFER;

    const swid_chip_info_t *c = &manifest->chip;
    if (append_u16(out, out_size, &p, 10, c->family) != SWID_OK ||
        append_u16(out, out_size, &p, 11, c->model) != SWID_OK ||
        append_u8(out, out_size, &p, 12, c->revision) != SWID_OK ||
        append_u8(out, out_size, &p, 13, c->cores) != SWID_OK ||
        append_u8(out, out_size, &p, 14, c->package) != SWID_OK ||
        append_u32(out, out_size, &p, 15, c->features) != SWID_OK ||
        append_u8(out, out_size, &p, 16, (uint8_t)c->status) != SWID_OK ||
        append_u8(out, out_size, &p, 17, (uint8_t)c->evidence) != SWID_OK) return SWID_ERR_BUFFER;

    const swid_identity_t *id = &manifest->identity;
    if (append_bytes(out, out_size, &p, 20, id->base_mac_valid ? id->base_mac : NULL,
                     id->base_mac_valid ? sizeof(id->base_mac) : 0) != SWID_OK ||
        append_bytes(out, out_size, &p, 21, id->optional_uid_valid ? id->optional_uid : NULL,
                     id->optional_uid_valid ? sizeof(id->optional_uid) : 0) != SWID_OK ||
        append_u8(out, out_size, &p, 22, id->optional_uid_bits) != SWID_OK ||
        append_u8(out, out_size, &p, 23, id->factory_calibration_present) != SWID_OK ||
        append_u8(out, out_size, &p, 24, (uint8_t)id->status) != SWID_OK ||
        append_u8(out, out_size, &p, 25, (uint8_t)id->evidence) != SWID_OK) return SWID_ERR_BUFFER;

    const swid_memory_info_t *mem = &manifest->memory;
    if (append_u32(out, out_size, &p, 30, mem->flash_jedec_id) != SWID_OK ||
        append_u32(out, out_size, &p, 31, mem->flash_capacity_bytes) != SWID_OK ||
        append_u64(out, out_size, &p, 32, mem->flash_unique_id_valid ? mem->flash_unique_id : 0) != SWID_OK ||
        append_u8(out, out_size, &p, 33, mem->flash_unique_id_valid) != SWID_OK ||
        append_u8(out, out_size, &p, 34, mem->flash_mode) != SWID_OK ||
        append_u8(out, out_size, &p, 35, mem->flash_manufacturer) != SWID_OK ||
        append_u8(out, out_size, &p, 36, mem->flash_type) != SWID_OK ||
        append_u8(out, out_size, &p, 37, mem->flash_capacity_code) != SWID_OK ||
        append_u32(out, out_size, &p, 38, mem->psram_capacity_bytes) != SWID_OK ||
        append_u8(out, out_size, &p, 39, mem->psram_present) != SWID_OK ||
        append_u8(out, out_size, &p, 40, mem->psram_interface) != SWID_OK ||
        append_u8(out, out_size, &p, 41, mem->psram_manufacturer) != SWID_OK ||
        append_u8(out, out_size, &p, 42, mem->psram_location) != SWID_OK ||
        append_u8(out, out_size, &p, 43, (uint8_t)mem->status) != SWID_OK ||
        append_u8(out, out_size, &p, 44, (uint8_t)mem->evidence) != SWID_OK)
        return SWID_ERR_BUFFER;

    const swid_radio_info_t *r = &manifest->radio;
    if (append_u8(out, out_size, &p, 50, r->wifi_supported) != SWID_OK ||
        append_u8(out, out_size, &p, 51, r->wifi_generation) != SWID_OK ||
        append_u8(out, out_size, &p, 52, r->bluetooth_supported) != SWID_OK ||
        append_u8(out, out_size, &p, 53, r->ble_supported) != SWID_OK ||
        append_u8(out, out_size, &p, 54, r->bt_classic_supported) != SWID_OK ||
        append_bytes(out, out_size, &p, 55, r->sta_mac, sizeof(r->sta_mac)) != SWID_OK ||
        append_bytes(out, out_size, &p, 56, r->ap_mac, sizeof(r->ap_mac)) != SWID_OK ||
        append_bytes(out, out_size, &p, 57, r->bt_mac, sizeof(r->bt_mac)) != SWID_OK ||
        append_u8(out, out_size, &p, 58, r->derived_mac_count) != SWID_OK ||
        append_u8(out, out_size, &p, 59, r->rf_calibration_present) != SWID_OK ||
        append_u8(out, out_size, &p, 60, (uint8_t)r->status) != SWID_OK ||
        append_u8(out, out_size, &p, 61, (uint8_t)r->evidence) != SWID_OK) return SWID_ERR_BUFFER;

    if (append_u8(out, out_size, &p, 70, (uint8_t)manifest->peripherals.status) != SWID_OK ||
        append_u8(out, out_size, &p, 71, (uint8_t)manifest->peripherals.evidence) != SWID_OK) return SWID_ERR_BUFFER;
    for (uint32_t type = 0; type < SWID_PERIPH_MAX; ++type) {
        for (size_t i = 0; i < manifest->peripherals.count; ++i) {
            const swid_peripheral_t *item = &manifest->peripherals.items[i];
            if ((uint32_t)item->type != type) continue;
            uint8_t encoded[11] = {(uint8_t)item->type, item->supported, item->controller_count,
                (uint8_t)item->channel_count, (uint8_t)(item->channel_count >> 8),
                (uint8_t)item->status, (uint8_t)item->evidence,
                (uint8_t)item->feature_flags, (uint8_t)(item->feature_flags >> 8),
                (uint8_t)(item->feature_flags >> 16), (uint8_t)(item->feature_flags >> 24)};
            if (append_bytes(out, out_size, &p, 80, encoded, sizeof(encoded)) != SWID_OK) return SWID_ERR_BUFFER;
        }
    }
    *written = p;
    return SWID_OK;
}

swid_err_t swid_serialize_fingerprint_input(const swid_manifest_t *manifest, swid_fingerprint_kind_t kind, uint8_t *out, size_t out_size, size_t *written) {
    if (kind < SWID_FP_SILICON || kind > SWID_FP_PROFILE) return SWID_ERR_ARG;
    return serialize_kind(manifest, kind, out, out_size, written);
}

swid_err_t swid_get_fingerprint(swid_fingerprint_kind_t kind, uint8_t out[32]) {
    uint8_t canonical[4096]; size_t written = 0; if (!out) return SWID_ERR_ARG; if (!g_initialized) return SWID_ERR_NOT_INITIALIZED;
    if (kind < SWID_FP_SILICON || kind > SWID_FP_PROFILE) return SWID_ERR_ARG;
    swid_err_t err = serialize_kind(&g_manifest, kind, canonical, sizeof(canonical), &written); if (err != SWID_OK) return err;
    return swid_port_hash256(canonical, written, out);
}
