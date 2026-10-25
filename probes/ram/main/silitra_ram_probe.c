/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "silitra.h"
#include "../../../ports/silitra_port.h"

#include "esp_chip_info.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#ifndef SILITRA_RAM_PROBE_REPEAT_COUNT
#define SILITRA_RAM_PROBE_REPEAT_COUNT 50
#endif
#ifndef SILITRA_RAM_PROBE_RESTART_AFTER_CAPTURE
#define SILITRA_RAM_PROBE_RESTART_AFTER_CAPTURE 0
#endif
#ifndef SILITRA_RAM_PROBE_PROFILE_TIMINGS
#define SILITRA_RAM_PROBE_PROFILE_TIMINGS 0
#endif

static silitra_manifest_t manifest;
static silitra_sha256_input_buffer_t canonical;
static uint8_t digest[32];
static char hex[SILITRA_FINGERPRINT_INPUT_MAX_BYTES * 2u + 1u];
#if SILITRA_RAM_PROBE_PROFILE_TIMINGS
static uint8_t manifest_tlv[1024];
static size_t canonical_len;
static size_t manifest_tlv_len;
static silitra_fingerprint_kind_t benchmark_kind;

enum { BENCH_INIT, BENCH_GET_MANIFEST, BENCH_MANIFEST_TLV, BENCH_FP_TLV, BENCH_SHA256, BENCH_FINGERPRINT };

static silitra_err_t run_bench_operation(unsigned operation) {
    switch (operation) {
    case BENCH_INIT: return silitra_init();
    case BENCH_GET_MANIFEST: return silitra_get_manifest(&manifest);
    case BENCH_MANIFEST_TLV: return silitra_serialize_manifest(&manifest, manifest_tlv, sizeof(manifest_tlv), &manifest_tlv_len);
    case BENCH_FP_TLV: return silitra_serialize_fingerprint_input(&manifest, benchmark_kind, canonical.bytes, sizeof(canonical.bytes), &canonical_len);
    case BENCH_SHA256: return silitra_port_hash256(canonical.bytes, canonical_len, digest);
    case BENCH_FINGERPRINT: return silitra_get_fingerprint(benchmark_kind, digest);
    default: return SILITRA_ERR_ARG;
    }
}

static void emit_timing(unsigned operation, const char *name, unsigned samples) {
    uint32_t values[16];
    if (samples > sizeof(values) / sizeof(values[0])) samples = sizeof(values) / sizeof(values[0]);
    for (unsigned i = 0; i < samples; ++i) {
        const int64_t start = esp_timer_get_time();
        const silitra_err_t result = run_bench_operation(operation);
        const int64_t elapsed = esp_timer_get_time() - start;
        if (result != SILITRA_OK || elapsed < 0 || elapsed > UINT32_MAX) {
            printf("{\"type\":\"timing_error\",\"operation\":\"%s\",\"code\":%d}\n", name, (int)result);
            return;
        }
        values[i] = (uint32_t)elapsed;
    }
    for (unsigned i = 1; i < samples; ++i) {
        const uint32_t value = values[i]; unsigned j = i;
        while (j && values[j - 1] > value) { values[j] = values[j - 1]; --j; }
        values[j] = value;
    }
    const uint32_t median = samples & 1u ? values[samples / 2u] : (values[samples / 2u - 1u] + values[samples / 2u]) / 2u;
    printf("{\"type\":\"timing\",\"operation\":\"%s\",\"samples\":%u,\"min_us\":%" PRIu32 ",\"median_us\":%" PRIu32 ",\"max_us\":%" PRIu32 "}\n",
           name, samples, values[0], median, values[samples - 1u]);
}

static void emit_timing_profile(void) {
    emit_timing(BENCH_INIT, "silitra_init", 16);
    emit_timing(BENCH_GET_MANIFEST, "silitra_get_manifest", 16);
    emit_timing(BENCH_MANIFEST_TLV, "silitra_serialize_manifest", 16);
    for (unsigned i = 0; i < 3; ++i) {
        benchmark_kind = (silitra_fingerprint_kind_t)(i + 1u);
        emit_timing(BENCH_FP_TLV, i == 0 ? "silicon_tlv" : i == 1 ? "assembly_tlv" : "profile_tlv", 16);
        emit_timing(BENCH_SHA256, i == 0 ? "silicon_sha256" : i == 1 ? "assembly_sha256" : "profile_sha256", 16);
        emit_timing(BENCH_FINGERPRINT, i == 0 ? "silicon_fingerprint" : i == 1 ? "assembly_fingerprint" : "profile_fingerprint", 16);
    }
}
#endif

static void to_hex(const uint8_t *in, size_t n, char *out) {
    static const char alphabet[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = alphabet[in[i] >> 4];
        out[i * 2 + 1] = alphabet[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

static void emit_fingerprint(silitra_fingerprint_kind_t kind, const char *name) {
    size_t n = 0;
    if (silitra_serialize_fingerprint_input(&manifest, kind, canonical.bytes, sizeof(canonical.bytes), &n) != SILITRA_OK ||
        silitra_port_hash256(canonical.bytes, n, digest) != SILITRA_OK || n * 2 >= sizeof(hex)) {
        printf("{\"type\":\"error\",\"operation\":\"fingerprint\",\"kind\":\"%s\"}\n", name);
        return;
    }
    to_hex(canonical.bytes, n, hex);
    char digest_hex[65];
    to_hex(digest, sizeof(digest), digest_hex);
    printf("{\"type\":\"fingerprint\",\"schema\":%u,\"kind\":\"%s\",\"tlv_hex\":\"%s\",\"sha256\":\"%s\"}\n",
           SILITRA_SCHEMA_VERSION, name, hex, digest_hex);
}

static void emit_repeat_samples(void) {
    uint8_t baseline[3][32], current[3][32], last[3][32];
    const silitra_fingerprint_kind_t kinds[] = {SILITRA_FP_SILICON, SILITRA_FP_ASSEMBLY, SILITRA_FP_PROFILE};
    uint32_t mismatches[3] = {0, 0, 0};
    uint64_t elapsed_total = 0;
    uint32_t elapsed_min = UINT32_MAX, elapsed_max = 0;
    char first_hex[3][65], last_hex[3][65];
    for (unsigned kind = 0; kind < 3; ++kind) {
        if (silitra_get_fingerprint(kinds[kind], baseline[kind]) != SILITRA_OK) {
            printf("{\"type\":\"repeat_error\",\"index\":0,\"code\":-1}\n");
            fflush(stdout);
            return;
        }
        memcpy(last[kind], baseline[kind], sizeof(last[kind]));
        to_hex(baseline[kind], sizeof(baseline[kind]), first_hex[kind]);
    }
    for (unsigned index = 0; index < SILITRA_RAM_PROBE_REPEAT_COUNT; ++index) {
        const int64_t started = esp_timer_get_time();
        silitra_err_t err = silitra_init();
        if (err == SILITRA_OK) err = silitra_get_manifest(&manifest);
        for (unsigned kind = 0; err == SILITRA_OK && kind < 3; ++kind)
            err = silitra_get_fingerprint(kinds[kind], current[kind]);
        if (err != SILITRA_OK) {
            printf("{\"type\":\"repeat_error\",\"index\":%u,\"code\":%d}\n", index, (int)err);
            fflush(stdout);
            return;
        }
        for (unsigned kind = 0; kind < 3; ++kind) {
            if (memcmp(current[kind], baseline[kind], sizeof(current[kind])) != 0) ++mismatches[kind];
            memcpy(last[kind], current[kind], sizeof(last[kind]));
        }
        const uint32_t elapsed = (uint32_t)(esp_timer_get_time() - started);
        elapsed_total += elapsed;
        if (elapsed < elapsed_min) elapsed_min = elapsed;
        if (elapsed > elapsed_max) elapsed_max = elapsed;
    }
    for (unsigned kind = 0; kind < 3; ++kind) to_hex(last[kind], sizeof(last[kind]), last_hex[kind]);
    printf("{\"type\":\"repeat_summary\",\"count\":%u,\"silicon_mismatches\":%" PRIu32
           ",\"assembly_mismatches\":%" PRIu32 ",\"profile_mismatches\":%" PRIu32
           ",\"first_silicon\":\"%s\",\"last_silicon\":\"%s\",\"first_assembly\":\"%s\",\"last_assembly\":\"%s\",\"first_profile\":\"%s\",\"last_profile\":\"%s\",\"collection_min_us\":%" PRIu32
           ",\"collection_max_us\":%" PRIu32 ",\"collection_total_us\":%" PRIu64 "}\n",
           (unsigned)SILITRA_RAM_PROBE_REPEAT_COUNT, mismatches[0], mismatches[1], mismatches[2],
           first_hex[0], last_hex[0], first_hex[1], last_hex[1], first_hex[2], last_hex[2],
           elapsed_min, elapsed_max, elapsed_total);
    fflush(stdout);
}

void app_main(void) {
    const int64_t begin = esp_timer_get_time();
    const silitra_err_t init = silitra_init();
    const int64_t initialized = esp_timer_get_time();
    if (init != SILITRA_OK || silitra_get_manifest(&manifest) != SILITRA_OK) {
        printf("{\"type\":\"error\",\"operation\":\"silitra_init\",\"code\":%d}\n", (int)init);
        for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
    }

    /* Give the host time to re-open USB Serial/JTAG after esptool releases it.
     * Without this handoff pause, the USB console can discard early output. */
    vTaskDelay(pdMS_TO_TICKS(2000));

    const unsigned sha_input_alignment = (unsigned)((uintptr_t)canonical.bytes % SILITRA_SHA256_INPUT_ALIGNMENT);
    printf("{\"type\":\"swid_ram_probe\",\"schema\":%u,\"target\":\"%s\",\"build_type\":\"RAM\",\"flash_write_attempted\":false,\"efuse_write_attempted\":false,\"init_us\":%" PRId64 ",\"free_internal_heap\":%u,\"stack_high_water_bytes\":%u,\"sha_input_alignment_remainder\":%u}\n",
           SILITRA_SCHEMA_VERSION, CONFIG_IDF_TARGET, initialized - begin,
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
           (unsigned)uxTaskGetStackHighWaterMark(NULL), sha_input_alignment);
    printf("{\"type\":\"chip\",\"family\":%u,\"model\":%u,\"revision\":%u,\"cores\":%u,\"package\":%u,\"features\":%" PRIu32 ",\"status\":%u,\"evidence\":%u}\n",
           manifest.chip.family, manifest.chip.model, manifest.chip.revision, manifest.chip.cores,
           manifest.chip.package, manifest.chip.features, manifest.chip.status, manifest.chip.evidence);

    printf("{\"type\":\"identity\",\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"mac_valid\":%u,\"optional_uid\":\"",
           manifest.identity.base_mac[0], manifest.identity.base_mac[1], manifest.identity.base_mac[2],
           manifest.identity.base_mac[3], manifest.identity.base_mac[4], manifest.identity.base_mac[5],
           manifest.identity.base_mac_valid);
    for (size_t i = 0; i < sizeof(manifest.identity.optional_uid); ++i) printf("%02X", manifest.identity.optional_uid[i]);
    printf("\",\"optional_uid_bits\":%u,\"optional_uid_valid\":%u}\n",
           manifest.identity.optional_uid_bits, manifest.identity.optional_uid_valid);

    printf("{\"type\":\"memory\",\"jedec\":%" PRIu32 ",\"flash_capacity\":%" PRIu32 ",\"flash_uid\":\"%016" PRIX64 "\",\"flash_uid_valid\":%u,\"psram_capacity\":%" PRIu32 ",\"psram_present\":%u,\"psram_interface\":%u,\"psram_location\":%u}\n",
           manifest.memory.flash_jedec_id, manifest.memory.flash_capacity_bytes, manifest.memory.flash_unique_id,
           manifest.memory.flash_unique_id_valid, manifest.memory.psram_capacity_bytes, manifest.memory.psram_present,
           manifest.memory.psram_interface, manifest.memory.psram_location);
    printf("{\"type\":\"radio\",\"wifi\":%u,\"wifi_generation\":%u,\"bluetooth\":%u,\"ble\":%u,\"bt_classic\":%u,\"sta_mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"ap_mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"bt_mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"derived_mac_count\":%u}\n",
           manifest.radio.wifi_supported, manifest.radio.wifi_generation, manifest.radio.bluetooth_supported,
           manifest.radio.ble_supported, manifest.radio.bt_classic_supported,
           manifest.radio.sta_mac[0],manifest.radio.sta_mac[1],manifest.radio.sta_mac[2],manifest.radio.sta_mac[3],manifest.radio.sta_mac[4],manifest.radio.sta_mac[5],
           manifest.radio.ap_mac[0],manifest.radio.ap_mac[1],manifest.radio.ap_mac[2],manifest.radio.ap_mac[3],manifest.radio.ap_mac[4],manifest.radio.ap_mac[5],
           manifest.radio.bt_mac[0],manifest.radio.bt_mac[1],manifest.radio.bt_mac[2],manifest.radio.bt_mac[3],manifest.radio.bt_mac[4],manifest.radio.bt_mac[5],
           manifest.radio.derived_mac_count);
    printf("{\"type\":\"peripheral_count\",\"count\":%u}\n", (unsigned)manifest.peripherals.count);
    for (size_t i = 0; i < manifest.peripherals.count; ++i) {
        const silitra_peripheral_t *p = &manifest.peripherals.items[i];
        printf("{\"type\":\"peripheral\",\"peripheral_type\":%u,\"supported\":%u,\"controllers\":%u,\"channels\":%u,\"feature_flags\":%" PRIu32 ",\"status\":%u,\"evidence\":%u}\n",
               p->type, p->supported, p->controller_count, p->channel_count, p->feature_flags, p->status, p->evidence);
    }
    emit_fingerprint(SILITRA_FP_SILICON, "silicon");
    emit_fingerprint(SILITRA_FP_ASSEMBLY, "assembly");
    emit_fingerprint(SILITRA_FP_PROFILE, "profile");
    emit_repeat_samples();
#if SILITRA_RAM_PROBE_PROFILE_TIMINGS
    emit_timing_profile();
#endif
    printf("{\"type\":\"resource_summary\",\"configured_main_stack_bytes\":%u,\"stack_high_water_bytes\":%u,\"free_internal_heap_bytes\":%u}\n",
           (unsigned)CONFIG_ESP_MAIN_TASK_STACK_SIZE,
           (unsigned)uxTaskGetStackHighWaterMark(NULL),
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
#if SILITRA_RAM_PROBE_RESTART_AFTER_CAPTURE
    printf("{\"type\":\"software_reset_request\",\"method\":\"esp_restart\",\"flash_write_attempted\":false}\n");
#endif
    printf("{\"type\":\"complete\",\"flash_write_attempted\":false,\"efuse_write_attempted\":false}\n");
    fflush(stdout);
#if SILITRA_RAM_PROBE_RESTART_AFTER_CAPTURE
    vTaskDelay(pdMS_TO_TICKS(250));
    esp_restart();
#endif
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}
