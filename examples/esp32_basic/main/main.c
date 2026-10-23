#include "swid.h"
#include "esp_log.h"

static const char *TAG = "swid_basic";

void app_main(void) {
    uint8_t digest[32];
    swid_identity_t identity;
    if (swid_init() != SWID_OK || swid_get_identity(&identity) != SWID_OK ||
        swid_get_fingerprint(SWID_FP_SILICON, digest) != SWID_OK) {
        ESP_LOGE(TAG, "SWID initialization/read failed");
        return;
    }
    ESP_LOGI(TAG, "Factory MAC %02X:%02X:%02X:%02X:%02X:%02X",
             identity.base_mac[0], identity.base_mac[1], identity.base_mac[2],
             identity.base_mac[3], identity.base_mac[4], identity.base_mac[5]);
    ESP_LOGI(TAG, "SiliconFingerprint256 ready (do not treat public identity as secret)");
}
