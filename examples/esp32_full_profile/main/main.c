#include "swid.h"
#include "esp_log.h"

static const char *TAG = "swid_profile";

void app_main(void) {
    swid_manifest_t manifest;
    uint8_t silicon[32], assembly[32], profile[32];
    if (swid_init() != SWID_OK || swid_get_manifest(&manifest) != SWID_OK ||
        swid_get_fingerprint(SWID_FP_SILICON, silicon) != SWID_OK ||
        swid_get_fingerprint(SWID_FP_ASSEMBLY, assembly) != SWID_OK ||
        swid_get_fingerprint(SWID_FP_PROFILE, profile) != SWID_OK) {
        ESP_LOGE(TAG, "SWID profile collection failed");
        return;
    }
    ESP_LOGI(TAG, "model=%u revision=%u cores=%u peripheral_entries=%u",
             manifest.chip.model, manifest.chip.revision, manifest.chip.cores,
             (unsigned)manifest.peripherals.count);
    ESP_LOGI(TAG, "three schema-v2 digests computed; serialize with swid_serialize_fingerprint_input() as needed");
}
