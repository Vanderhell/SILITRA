/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "silitra.h"
#include "esp_log.h"

static const char *TAG = "silitra_profile";

void app_main(void) {
    silitra_manifest_t manifest;
    uint8_t silicon[32], assembly[32], profile[32];
    if (silitra_init() != SILITRA_OK || silitra_get_manifest(&manifest) != SILITRA_OK ||
        silitra_get_fingerprint(SILITRA_FP_SILICON, silicon) != SILITRA_OK ||
        silitra_get_fingerprint(SILITRA_FP_ASSEMBLY, assembly) != SILITRA_OK ||
        silitra_get_fingerprint(SILITRA_FP_PROFILE, profile) != SILITRA_OK) {
        ESP_LOGE(TAG, "SILITRA profile collection failed");
        return;
    }
    ESP_LOGI(TAG, "model=%u revision=%u cores=%u peripheral_entries=%u",
             manifest.chip.model, manifest.chip.revision, manifest.chip.cores,
             (unsigned)manifest.peripherals.count);
    ESP_LOGI(TAG, "three schema-v2 digests computed; serialize with silitra_serialize_fingerprint_input() as needed");
}
