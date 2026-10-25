/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "silitra.h"
#include "esp_log.h"

static const char *TAG = "silitra_basic";

void app_main(void) {
    uint8_t digest[32];
    silitra_identity_t identity;
    if (silitra_init() != SILITRA_OK || silitra_get_identity(&identity) != SILITRA_OK ||
        silitra_get_fingerprint(SILITRA_FP_SILICON, digest) != SILITRA_OK) {
        ESP_LOGE(TAG, "SILITRA initialization/read failed");
        return;
    }
    ESP_LOGI(TAG, "Factory MAC %02X:%02X:%02X:%02X:%02X:%02X",
             identity.base_mac[0], identity.base_mac[1], identity.base_mac[2],
             identity.base_mac[3], identity.base_mac[4], identity.base_mac[5]);
    ESP_LOGI(TAG, "SiliconFingerprint256 ready (do not treat public identity as secret)");
}
