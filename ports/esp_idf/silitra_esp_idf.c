/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "../../include/silitra.h"
#include "../silitra_port.h"

#include "esp_chip_info.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_flash.h"
#include "esp_mac.h"
#include "esp_psram.h"
#if defined(CONFIG_IDF_TARGET_ESP32)
#include "esp32/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
#include "esp32s2/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
#include "esp32s3/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C2)
#include "esp32c2/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
#include "esp32c3/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C5)
#include "esp32c5/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
#include "esp32c6/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32C61)
#include "esp32c61/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32H2)
#include "esp32h2/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32H21)
#include "esp32h21/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32H4)
#include "esp32h4/rom/sha.h"
#elif defined(CONFIG_IDF_TARGET_ESP32P4)
#include "esp32p4/rom/sha.h"
#else
#error "SILITRA ROM SHA adapter is not implemented for this ESP-IDF target"
#endif
#include "soc/soc_caps.h"

#include <string.h>

/* Keep the public profile independent of the exact SOC capability macro set.
 * Missing count macros mean "not exposed by this IDF target", not zero silicon. */
#ifndef SOC_DAC_SUPPORTED
#define SOC_DAC_SUPPORTED 0
#endif
#ifdef SOC_ADC_SUPPORTED
#define SILITRA_SOC_ADC_KNOWN 1
#else
#define SOC_ADC_SUPPORTED 0
#define SILITRA_SOC_ADC_KNOWN 0
#endif
#ifdef SOC_I2S_SUPPORTED
#define SILITRA_SOC_I2S_KNOWN 1
#else
#define SOC_I2S_SUPPORTED 0
#define SILITRA_SOC_I2S_KNOWN 0
#endif
#ifdef SOC_GPSPI_SUPPORTED
#define SILITRA_SOC_GPSPI_KNOWN 1
#else
#define SOC_GPSPI_SUPPORTED 0
#define SILITRA_SOC_GPSPI_KNOWN 0
#endif
#ifdef SOC_I2C_SUPPORTED
#define SILITRA_SOC_I2C_KNOWN 1
#else
#define SOC_I2C_SUPPORTED 0
#define SILITRA_SOC_I2C_KNOWN 0
#endif
#ifndef SOC_DAC_CHAN_NUM
#define SOC_DAC_CHAN_NUM 0
#endif
#ifndef SOC_RTCIO_PIN_COUNT
#define SOC_RTCIO_PIN_COUNT 0
#endif
#ifndef SOC_LEDC_SUPPORTED
#define SOC_LEDC_SUPPORTED 0
#endif
#ifndef SOC_MCPWM_SUPPORTED
#define SOC_MCPWM_SUPPORTED 0
#endif
#ifndef SOC_MCPWM_GROUPS
#define SOC_MCPWM_GROUPS 0
#endif
#ifndef SOC_RMT_SUPPORTED
#define SOC_RMT_SUPPORTED 0
#endif
#ifndef SOC_RMT_GROUPS
#define SOC_RMT_GROUPS 0
#endif
#ifndef SOC_PCNT_SUPPORTED
#define SOC_PCNT_SUPPORTED 0
#endif
#ifndef SOC_PCNT_UNITS_PER_GROUP
#define SOC_PCNT_UNITS_PER_GROUP 0
#endif
#ifndef SOC_PCNT_CHANNELS_PER_UNIT
#define SOC_PCNT_CHANNELS_PER_UNIT 0
#endif
#ifndef SOC_GPTIMER_SUPPORTED
#define SOC_GPTIMER_SUPPORTED 0
#endif
#ifndef SOC_GPTIMER_GROUPS
#define SOC_GPTIMER_GROUPS 0
#endif
#ifndef SOC_GPTIMER_TIMERS_PER_GROUP
#define SOC_GPTIMER_TIMERS_PER_GROUP 0
#endif
#ifndef SOC_WDT_SUPPORTED
#define SOC_WDT_SUPPORTED 0
#endif
#ifndef SOC_GDMA_SUPPORTED
#define SOC_GDMA_SUPPORTED 0
#endif
#ifndef SOC_GDMA_NUM_GROUPS_MAX
#define SOC_GDMA_NUM_GROUPS_MAX 0
#endif
#ifndef SOC_TWAI_SUPPORTED
#define SOC_TWAI_SUPPORTED 0
#endif
#ifndef SOC_TWAI_CONTROLLER_NUM
#define SOC_TWAI_CONTROLLER_NUM 0
#endif
#ifndef SOC_USB_OTG_SUPPORTED
#define SOC_USB_OTG_SUPPORTED 0
#endif
#ifndef SOC_USB_SERIAL_JTAG_SUPPORTED
#define SOC_USB_SERIAL_JTAG_SUPPORTED 0
#endif
#ifndef SOC_SDMMC_HOST_SUPPORTED
#define SOC_SDMMC_HOST_SUPPORTED 0
#endif
#ifndef SOC_SDMMC_SLOT_NUM
#define SOC_SDMMC_SLOT_NUM 0
#endif
#ifndef SOC_TOUCH_SENSOR_SUPPORTED
#define SOC_TOUCH_SENSOR_SUPPORTED 0
#endif
#ifndef SOC_TOUCH_SENSOR_NUM
#define SOC_TOUCH_SENSOR_NUM 0
#endif
#ifndef SOC_TEMP_SENSOR_SUPPORTED
#define SOC_TEMP_SENSOR_SUPPORTED 0
#endif
#ifndef SOC_RNG_SUPPORTED
#define SOC_RNG_SUPPORTED 0
#endif
#ifndef SOC_AES_SUPPORTED
#define SOC_AES_SUPPORTED 0
#endif
#ifndef SOC_SHA_SUPPORTED
#define SOC_SHA_SUPPORTED 0
#endif
#ifndef SOC_MPI_SUPPORTED
#define SOC_MPI_SUPPORTED 0
#endif
#ifndef SOC_HMAC_SUPPORTED
#define SOC_HMAC_SUPPORTED 0
#endif
#ifndef SOC_DIG_SIGN_SUPPORTED
#define SOC_DIG_SIGN_SUPPORTED 0
#endif
#ifndef SOC_SECURE_BOOT_SUPPORTED
#define SOC_SECURE_BOOT_SUPPORTED 0
#endif
#ifndef SOC_FLASH_ENC_SUPPORTED
#define SOC_FLASH_ENC_SUPPORTED 0
#endif
#ifndef SOC_WIFI_SUPPORTED
#define SOC_WIFI_SUPPORTED 0
#endif
#ifndef SOC_BT_SUPPORTED
#define SOC_BT_SUPPORTED 0
#endif
#ifndef SOC_EMAC_SUPPORTED
#define SOC_EMAC_SUPPORTED 0
#endif
#ifndef SOC_LP_CORE_SUPPORTED
#define SOC_LP_CORE_SUPPORTED 0
#endif
#ifndef SOC_ULP_SUPPORTED
#define SOC_ULP_SUPPORTED 0
#endif
#ifndef SOC_BLE_SUPPORTED
#define SOC_BLE_SUPPORTED SOC_BT_SUPPORTED
#endif
#ifndef SOC_BT_CLASSIC_SUPPORTED
/* IDF 5.5.1 SoC headers expose generic BT and BLE, but not Classic. Generic
 * BT denotes the controller family and must not be promoted to Classic. */
#define SOC_BT_CLASSIC_SUPPORTED 0
#endif
#if (defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3)) && SOC_BT_CLASSIC_SUPPORTED
#error "ESP32-S3/C3 capability adapter must not report Bluetooth Classic"
#endif

static void add_peripheral_ex(silitra_peripheral_profile_t *p, silitra_peripheral_type_t type,
                              uint8_t supported, uint8_t controllers, uint16_t channels, uint8_t known) {
    if (p->count >= SILITRA_MAX_PERIPHERALS) return;
    silitra_peripheral_t *item = &p->items[p->count++];
    item->type = type; item->supported = supported; item->controller_count = controllers; item->channel_count = channels;
    item->status = !known ? SILITRA_UNKNOWN : (supported ? SILITRA_SUPPORTED : SILITRA_UNAVAILABLE);
    item->evidence = SILITRA_EVIDENCE_BUILD_CAPABILITY;
}

static void mark_peripheral_unknown(silitra_peripheral_profile_t *p, silitra_peripheral_type_t type) {
    for (size_t i = 0; i < p->count; ++i) {
        if (p->items[i].type == type) {
            p->items[i].status = SILITRA_UNKNOWN;
            p->items[i].evidence = SILITRA_EVIDENCE_UNKNOWN;
            return;
        }
    }
}

#define add_peripheral(p, type, supported, controllers, channels) \
    add_peripheral_ex((p), (type), (supported), (controllers), (channels), 1)

#ifdef SOC_UART_NUM
#define SILITRA_UART_COUNT SOC_UART_NUM
#else
#define SILITRA_UART_COUNT 0
#endif
#ifdef SOC_SPI_PERIPH_NUM
#define SILITRA_SPI_COUNT SOC_SPI_PERIPH_NUM
#else
#define SILITRA_SPI_COUNT 0
#endif
#ifdef SOC_I2C_NUM
#define SILITRA_I2C_COUNT SOC_I2C_NUM
#else
#define SILITRA_I2C_COUNT 0
#endif
#ifdef SOC_I2S_NUM
#define SILITRA_I2S_COUNT SOC_I2S_NUM
#else
#define SILITRA_I2S_COUNT 0
#endif
#ifdef SOC_ADC_PERIPH_NUM
#define SILITRA_ADC_COUNT SOC_ADC_PERIPH_NUM
#else
#define SILITRA_ADC_COUNT 0
#endif
#ifdef SOC_GPIO_PIN_COUNT
#define SILITRA_GPIO_COUNT SOC_GPIO_PIN_COUNT
#else
#define SILITRA_GPIO_COUNT 0
#endif
#ifdef SOC_LEDC_CHANNEL_NUM
#define SILITRA_LEDC_CHANNELS SOC_LEDC_CHANNEL_NUM
#else
#define SILITRA_LEDC_CHANNELS 0
#endif

#if defined(SILITRA_PROFILE_FULL)
static void collect_peripherals(silitra_peripheral_profile_t *p) {
    memset(p, 0, sizeof(*p));
    add_peripheral(p, SILITRA_PERIPH_UART, SOC_UART_SUPPORTED, SILITRA_UART_COUNT, 0);
    add_peripheral_ex(p, SILITRA_PERIPH_SPI, SOC_GPSPI_SUPPORTED, SILITRA_SPI_COUNT, 0, SILITRA_SOC_GPSPI_KNOWN);
    add_peripheral_ex(p, SILITRA_PERIPH_I2C, SOC_I2C_SUPPORTED, SILITRA_I2C_COUNT, 0, SILITRA_SOC_I2C_KNOWN);
    add_peripheral_ex(p, SILITRA_PERIPH_I2S, SOC_I2S_SUPPORTED, SILITRA_I2S_COUNT, 0, SILITRA_SOC_I2S_KNOWN);
    add_peripheral_ex(p, SILITRA_PERIPH_ADC, SOC_ADC_SUPPORTED, SILITRA_ADC_COUNT, SOC_ADC_MAX_CHANNEL_NUM, SILITRA_SOC_ADC_KNOWN);
    add_peripheral(p, SILITRA_PERIPH_DAC, SOC_DAC_SUPPORTED, SOC_DAC_CHAN_NUM, SOC_DAC_CHAN_NUM);
    add_peripheral(p, SILITRA_PERIPH_GPIO, 1, 1, SILITRA_GPIO_COUNT);
    add_peripheral(p, SILITRA_PERIPH_RTC_GPIO, SOC_RTCIO_PIN_COUNT > 0, 1, SOC_RTCIO_PIN_COUNT);
    add_peripheral(p, SILITRA_PERIPH_LEDC, SOC_LEDC_SUPPORTED, 1, SILITRA_LEDC_CHANNELS);
    add_peripheral(p, SILITRA_PERIPH_MCPWM, SOC_MCPWM_SUPPORTED, SOC_MCPWM_GROUPS, 0);
    add_peripheral(p, SILITRA_PERIPH_RMT, SOC_RMT_SUPPORTED, SOC_RMT_GROUPS, 0);
    add_peripheral(p, SILITRA_PERIPH_PCNT, SOC_PCNT_SUPPORTED, SOC_PCNT_UNITS_PER_GROUP, SOC_PCNT_CHANNELS_PER_UNIT);
    add_peripheral(p, SILITRA_PERIPH_GPTIMER, SOC_GPTIMER_SUPPORTED, SOC_GPTIMER_GROUPS, SOC_GPTIMER_TIMERS_PER_GROUP);
    add_peripheral(p, SILITRA_PERIPH_WATCHDOG, SOC_WDT_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_DMA, SOC_GDMA_SUPPORTED, SOC_GDMA_NUM_GROUPS_MAX, 0);
    add_peripheral(p, SILITRA_PERIPH_TWAI, SOC_TWAI_SUPPORTED, SOC_TWAI_CONTROLLER_NUM, 0);
    add_peripheral(p, SILITRA_PERIPH_USB_OTG, SOC_USB_OTG_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_USB_SERIAL_JTAG, SOC_USB_SERIAL_JTAG_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_SDMMC, SOC_SDMMC_HOST_SUPPORTED, 1, SOC_SDMMC_SLOT_NUM);
    add_peripheral(p, SILITRA_PERIPH_TOUCH, SOC_TOUCH_SENSOR_SUPPORTED, 1, SOC_TOUCH_SENSOR_NUM);
    add_peripheral(p, SILITRA_PERIPH_TEMPERATURE, SOC_TEMP_SENSOR_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_RNG, SOC_RNG_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_AES, SOC_AES_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_SHA, SOC_SHA_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_RSA, SOC_MPI_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_HMAC, SOC_HMAC_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_DIGITAL_SIGNATURE, SOC_DIG_SIGN_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_SECURE_BOOT, SOC_SECURE_BOOT_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_FLASH_ENCRYPTION, SOC_FLASH_ENC_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_WIFI, SOC_WIFI_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_BLUETOOTH, SOC_BT_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_ETHERNET, SOC_EMAC_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_LP_CPU, SOC_LP_CORE_SUPPORTED, 1, 0);
    add_peripheral(p, SILITRA_PERIPH_ULP, SOC_ULP_SUPPORTED, 1, 0);
    p->status = SILITRA_DETECTED; p->evidence = SILITRA_EVIDENCE_BUILD_CAPABILITY;
#if defined(CONFIG_IDF_TARGET_ESP32H4)
    /* IDF 5.5.1 explicitly leaves these H4 SOC_* entries as TODO/commented
     * in soc_caps.h. Zero fallback values must not be interpreted as silicon absence. */
    mark_peripheral_unknown(p, SILITRA_PERIPH_ADC);
    mark_peripheral_unknown(p, SILITRA_PERIPH_DAC);
    mark_peripheral_unknown(p, SILITRA_PERIPH_SPI);
    mark_peripheral_unknown(p, SILITRA_PERIPH_I2C);
    mark_peripheral_unknown(p, SILITRA_PERIPH_I2S);
    mark_peripheral_unknown(p, SILITRA_PERIPH_LEDC);
    mark_peripheral_unknown(p, SILITRA_PERIPH_MCPWM);
    mark_peripheral_unknown(p, SILITRA_PERIPH_RMT);
    mark_peripheral_unknown(p, SILITRA_PERIPH_PCNT);
    mark_peripheral_unknown(p, SILITRA_PERIPH_TWAI);
    mark_peripheral_unknown(p, SILITRA_PERIPH_USB_OTG);
    mark_peripheral_unknown(p, SILITRA_PERIPH_USB_SERIAL_JTAG);
    mark_peripheral_unknown(p, SILITRA_PERIPH_TEMPERATURE);
    mark_peripheral_unknown(p, SILITRA_PERIPH_BLUETOOTH);
    mark_peripheral_unknown(p, SILITRA_PERIPH_LP_CPU);
    mark_peripheral_unknown(p, SILITRA_PERIPH_ULP);
    p->status = SILITRA_UNKNOWN;
#elif defined(CONFIG_IDF_TARGET_ESP32H21)
    /* H21 IDF 5.5.1 SoC headers also leave the following entries undocumented. */
    mark_peripheral_unknown(p, SILITRA_PERIPH_ADC);
    mark_peripheral_unknown(p, SILITRA_PERIPH_I2S);
    mark_peripheral_unknown(p, SILITRA_PERIPH_LEDC);
    mark_peripheral_unknown(p, SILITRA_PERIPH_PCNT);
    mark_peripheral_unknown(p, SILITRA_PERIPH_MCPWM);
    mark_peripheral_unknown(p, SILITRA_PERIPH_TWAI);
    mark_peripheral_unknown(p, SILITRA_PERIPH_RMT);
    mark_peripheral_unknown(p, SILITRA_PERIPH_USB_SERIAL_JTAG);
    mark_peripheral_unknown(p, SILITRA_PERIPH_TEMPERATURE);
    mark_peripheral_unknown(p, SILITRA_PERIPH_ULP);
    mark_peripheral_unknown(p, SILITRA_PERIPH_BLUETOOTH);
    p->status = SILITRA_UNKNOWN;
#endif
}
#undef add_peripheral
#endif

silitra_err_t silitra_port_collect(silitra_manifest_t *out) {
    if (!out) return SILITRA_ERR_ARG;
    memset(out, 0, sizeof(*out));
    esp_chip_info_t ci; esp_chip_info(&ci);
    out->chip.family = 32; out->chip.model = (uint16_t)ci.model; out->chip.revision = (uint8_t)ci.revision; out->chip.cores = (uint8_t)ci.cores; out->chip.features = ci.features; out->chip.package = (uint8_t)esp_efuse_get_pkg_ver(); out->chip.status = SILITRA_DETECTED; out->chip.evidence = SILITRA_EVIDENCE_RUNTIME_READ;
    esp_read_mac(out->identity.base_mac, ESP_MAC_WIFI_STA); out->identity.base_mac_valid = 1; out->identity.status = SILITRA_DETECTED; out->identity.evidence = SILITRA_EVIDENCE_RUNTIME_READ;
#if defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C6)
    if (esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, out->identity.optional_uid, 128) == ESP_OK) { out->identity.optional_uid_bits = 128; for (size_t i = 0; i < 16; ++i) out->identity.optional_uid_valid |= out->identity.optional_uid[i] != 0; }
#endif
#if !defined(SILITRA_PROFILE_MINIMAL)
    uint32_t flash_id = 0; (void)esp_flash_read_id(NULL, &flash_id); out->memory.flash_jedec_id = flash_id; out->memory.flash_manufacturer = (uint8_t)(flash_id >> 16); out->memory.flash_type = (uint8_t)(flash_id >> 8); out->memory.flash_capacity_code = (uint8_t)flash_id;
    /* Report the physical component size, not the usable size encoded in the
     * current app image header (which may be smaller or unavailable in RAM
     * loaded probes). This API is read-only and detects the flash geometry. */
    (void)esp_flash_get_physical_size(NULL, &out->memory.flash_capacity_bytes); out->memory.flash_unique_id_valid = esp_flash_read_unique_chip_id(NULL, &out->memory.flash_unique_id) == ESP_OK;
#if CONFIG_SPIRAM
    out->memory.psram_capacity_bytes = (uint32_t)esp_psram_get_size();
#else
    out->memory.psram_capacity_bytes = 0;
#endif
    out->memory.psram_present = out->memory.psram_capacity_bytes != 0; out->memory.psram_interface = out->memory.psram_present ? 8 : 0; out->memory.psram_location = out->memory.psram_present ? 0 : 255; out->memory.status = SILITRA_DETECTED; out->memory.evidence = SILITRA_EVIDENCE_RUNTIME_READ;
    /* These are silicon capabilities, deliberately sourced from soc_caps,
     * never CONFIG_BT_ENABLED / CONFIG_BT_NIMBLE_ENABLED build selections. */
    out->radio.wifi_supported = SOC_WIFI_SUPPORTED; out->radio.wifi_generation = SOC_WIFI_SUPPORTED ? 4 : 0; out->radio.bluetooth_supported = SOC_BT_SUPPORTED; out->radio.ble_supported = SOC_BLE_SUPPORTED; out->radio.bt_classic_supported = SOC_BT_CLASSIC_SUPPORTED;
    if (esp_read_mac(out->radio.sta_mac, ESP_MAC_WIFI_STA) == ESP_OK) out->radio.derived_mac_count++;
    if (esp_read_mac(out->radio.ap_mac, ESP_MAC_WIFI_SOFTAP) == ESP_OK) out->radio.derived_mac_count++;
    if (esp_read_mac(out->radio.bt_mac, ESP_MAC_BT) == ESP_OK) out->radio.derived_mac_count++;
    out->radio.status = SILITRA_DETECTED; out->radio.evidence = SILITRA_EVIDENCE_RUNTIME_READ;
#if defined(CONFIG_IDF_TARGET_ESP32H4) || defined(CONFIG_IDF_TARGET_ESP32H21)
    /* These targets have incomplete Wi-Fi/Bluetooth SoC capability declarations in IDF 5.5.1. */
    out->radio.status = SILITRA_UNKNOWN;
    out->radio.evidence = SILITRA_EVIDENCE_UNKNOWN;
#endif
#endif
#if defined(SILITRA_PROFILE_FULL)
    collect_peripherals(&out->peripherals); return SILITRA_OK;
#else
    out->peripherals.status = SILITRA_UNKNOWN; out->peripherals.evidence = SILITRA_EVIDENCE_UNKNOWN;
#endif
    return SILITRA_OK;
}

silitra_err_t silitra_port_hash256(const uint8_t *data, size_t len, uint8_t out[32]) {
    if (!data || !out) return SILITRA_ERR_ARG;
    if (((uintptr_t)data % SILITRA_SHA256_INPUT_ALIGNMENT) != 0u) return SILITRA_ERR_ARG;
#if defined(CONFIG_IDF_TARGET_ESP32)
    if (len > (SIZE_MAX / 8u)) return SILITRA_ERR_ARG;
    SHA_CTX ctx;
    ets_sha_enable();
    ets_sha_init(&ctx);
    ets_sha_update(&ctx, SHA2_256, data, len * 8u);
    ets_sha_finish(&ctx, SHA2_256, out);
    ets_sha_disable();
    return SILITRA_OK;
#else
    if (len > UINT32_MAX) return SILITRA_ERR_ARG;
    SHA_CTX ctx;
    ets_sha_enable();
    if (ets_sha_init(&ctx, SHA2_256) != 0) { ets_sha_disable(); return SILITRA_ERR_HASH; }
    ets_sha_update(&ctx, data, (uint32_t)len, false);
    return ets_sha_finish(&ctx, out) == 0 ? (ets_sha_disable(), SILITRA_OK) : (ets_sha_disable(), SILITRA_ERR_HASH);
#endif
}
