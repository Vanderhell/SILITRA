/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SILITRA_SCHEMA_VERSION 2u
#define SILITRA_LEGACY_SCHEMA_VERSION 1u
#define SILITRA_MANIFEST_SCHEMA_VERSION 1u
#define SILITRA_MAX_PERIPHERALS 48u
#define SILITRA_MAX_IDENTITY_BYTES 32u

typedef enum {
    SILITRA_OK = 0,
    SILITRA_ERR_ARG = -1,
    SILITRA_ERR_NOT_INITIALIZED = -2,
    SILITRA_ERR_UNSUPPORTED = -3,
    SILITRA_ERR_BUFFER = -4,
    SILITRA_ERR_READ = -5,
    SILITRA_ERR_HASH = -6,
    SILITRA_ERR_STATE = -7
} silitra_err_t;

typedef enum { SILITRA_UNKNOWN = 0, SILITRA_SUPPORTED, SILITRA_DETECTED, SILITRA_TESTED, SILITRA_UNAVAILABLE } silitra_status_t;
typedef enum { SILITRA_EVIDENCE_UNKNOWN = 0, SILITRA_EVIDENCE_BUILD_CAPABILITY, SILITRA_EVIDENCE_RUNTIME_READ, SILITRA_EVIDENCE_RUNTIME_TEST } silitra_evidence_t;
typedef enum { SILITRA_FP_SILICON = 1, SILITRA_FP_ASSEMBLY = 2, SILITRA_FP_PROFILE = 3 } silitra_fingerprint_kind_t;

typedef struct {
    uint16_t family;
    uint16_t model;
    uint8_t revision;
    uint8_t cores;
    uint8_t package;
    uint32_t features;
    silitra_status_t status;
    silitra_evidence_t evidence;
} silitra_chip_info_t;

typedef struct {
    uint8_t base_mac[6];
    uint8_t base_mac_valid;
    uint8_t optional_uid[16];
    uint8_t optional_uid_bits;
    uint8_t optional_uid_valid;
    uint8_t factory_calibration_present;
    silitra_status_t status;
    silitra_evidence_t evidence;
} silitra_identity_t;

typedef struct {
    uint32_t flash_jedec_id;
    uint32_t flash_capacity_bytes;
    uint64_t flash_unique_id;
    uint8_t flash_unique_id_valid;
    uint8_t flash_mode;
    uint8_t flash_manufacturer;
    uint8_t flash_type;
    uint8_t flash_capacity_code;
    uint32_t psram_capacity_bytes;
    uint8_t psram_present;
    uint8_t psram_interface;
    uint8_t psram_manufacturer;
    uint8_t psram_location;
    silitra_status_t status;
    silitra_evidence_t evidence;
} silitra_memory_info_t;

typedef struct {
    uint8_t wifi_supported;
    uint8_t wifi_generation;
    uint8_t bluetooth_supported;
    uint8_t ble_supported;
    uint8_t bt_classic_supported;
    uint8_t sta_mac[6];
    uint8_t ap_mac[6];
    uint8_t bt_mac[6];
    uint8_t derived_mac_count;
    uint8_t rf_calibration_present;
    silitra_status_t status;
    silitra_evidence_t evidence;
} silitra_radio_info_t;

typedef enum {
    SILITRA_PERIPH_UART, SILITRA_PERIPH_SPI, SILITRA_PERIPH_I2C, SILITRA_PERIPH_I2S,
    SILITRA_PERIPH_ADC, SILITRA_PERIPH_DAC, SILITRA_PERIPH_GPIO, SILITRA_PERIPH_RTC_GPIO,
    SILITRA_PERIPH_LEDC, SILITRA_PERIPH_MCPWM, SILITRA_PERIPH_RMT, SILITRA_PERIPH_PCNT,
    SILITRA_PERIPH_GPTIMER, SILITRA_PERIPH_WATCHDOG, SILITRA_PERIPH_DMA, SILITRA_PERIPH_TWAI,
    SILITRA_PERIPH_USB_OTG, SILITRA_PERIPH_USB_SERIAL_JTAG, SILITRA_PERIPH_SDMMC,
    SILITRA_PERIPH_TOUCH, SILITRA_PERIPH_TEMPERATURE, SILITRA_PERIPH_RNG, SILITRA_PERIPH_AES,
    SILITRA_PERIPH_SHA, SILITRA_PERIPH_RSA, SILITRA_PERIPH_HMAC, SILITRA_PERIPH_DIGITAL_SIGNATURE,
    SILITRA_PERIPH_SECURE_BOOT, SILITRA_PERIPH_FLASH_ENCRYPTION, SILITRA_PERIPH_WIFI,
    SILITRA_PERIPH_BLUETOOTH, SILITRA_PERIPH_ETHERNET, SILITRA_PERIPH_LP_CPU, SILITRA_PERIPH_ULP,
    SILITRA_PERIPH_MAX
} silitra_peripheral_type_t;

/* Maximum v2 profile input: 18 header + 29 chip + 33 memory + 20 radio
 * bytes and at most one 15-byte TLV per declared peripheral type. */
#define SILITRA_FINGERPRINT_INPUT_MAX_BYTES (100u + 15u * SILITRA_PERIPH_MAX)

typedef struct {
    silitra_peripheral_type_t type;
    uint8_t supported;
    uint8_t controller_count;
    uint16_t channel_count;
    uint32_t feature_flags;
    silitra_status_t status;
    silitra_evidence_t evidence;
} silitra_peripheral_t;

typedef struct {
    silitra_peripheral_t items[SILITRA_MAX_PERIPHERALS];
    size_t count;
    silitra_status_t status;
    silitra_evidence_t evidence;
} silitra_peripheral_profile_t;

typedef struct {
    silitra_chip_info_t chip;
    silitra_identity_t identity;
    silitra_memory_info_t memory;
    silitra_radio_info_t radio;
    silitra_peripheral_profile_t peripherals;
} silitra_manifest_t;
