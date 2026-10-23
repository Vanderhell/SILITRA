#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SWID_SCHEMA_VERSION 2u
#define SWID_LEGACY_SCHEMA_VERSION 1u
#define SWID_MANIFEST_SCHEMA_VERSION 1u
#define SWID_MAX_PERIPHERALS 48u
#define SWID_MAX_IDENTITY_BYTES 32u

typedef enum {
    SWID_OK = 0,
    SWID_ERR_ARG = -1,
    SWID_ERR_NOT_INITIALIZED = -2,
    SWID_ERR_UNSUPPORTED = -3,
    SWID_ERR_BUFFER = -4,
    SWID_ERR_READ = -5,
    SWID_ERR_HASH = -6,
    SWID_ERR_STATE = -7
} swid_err_t;

typedef enum { SWID_UNKNOWN = 0, SWID_SUPPORTED, SWID_DETECTED, SWID_TESTED, SWID_UNAVAILABLE } swid_status_t;
typedef enum { SWID_EVIDENCE_UNKNOWN = 0, SWID_EVIDENCE_BUILD_CAPABILITY, SWID_EVIDENCE_RUNTIME_READ, SWID_EVIDENCE_RUNTIME_TEST } swid_evidence_t;
typedef enum { SWID_FP_SILICON = 1, SWID_FP_ASSEMBLY = 2, SWID_FP_PROFILE = 3 } swid_fingerprint_kind_t;

typedef struct {
    uint16_t family;
    uint16_t model;
    uint8_t revision;
    uint8_t cores;
    uint8_t package;
    uint32_t features;
    swid_status_t status;
    swid_evidence_t evidence;
} swid_chip_info_t;

typedef struct {
    uint8_t base_mac[6];
    uint8_t base_mac_valid;
    uint8_t optional_uid[16];
    uint8_t optional_uid_bits;
    uint8_t optional_uid_valid;
    uint8_t factory_calibration_present;
    swid_status_t status;
    swid_evidence_t evidence;
} swid_identity_t;

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
    swid_status_t status;
    swid_evidence_t evidence;
} swid_memory_info_t;

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
    swid_status_t status;
    swid_evidence_t evidence;
} swid_radio_info_t;

typedef enum {
    SWID_PERIPH_UART, SWID_PERIPH_SPI, SWID_PERIPH_I2C, SWID_PERIPH_I2S,
    SWID_PERIPH_ADC, SWID_PERIPH_DAC, SWID_PERIPH_GPIO, SWID_PERIPH_RTC_GPIO,
    SWID_PERIPH_LEDC, SWID_PERIPH_MCPWM, SWID_PERIPH_RMT, SWID_PERIPH_PCNT,
    SWID_PERIPH_GPTIMER, SWID_PERIPH_WATCHDOG, SWID_PERIPH_DMA, SWID_PERIPH_TWAI,
    SWID_PERIPH_USB_OTG, SWID_PERIPH_USB_SERIAL_JTAG, SWID_PERIPH_SDMMC,
    SWID_PERIPH_TOUCH, SWID_PERIPH_TEMPERATURE, SWID_PERIPH_RNG, SWID_PERIPH_AES,
    SWID_PERIPH_SHA, SWID_PERIPH_RSA, SWID_PERIPH_HMAC, SWID_PERIPH_DIGITAL_SIGNATURE,
    SWID_PERIPH_SECURE_BOOT, SWID_PERIPH_FLASH_ENCRYPTION, SWID_PERIPH_WIFI,
    SWID_PERIPH_BLUETOOTH, SWID_PERIPH_ETHERNET, SWID_PERIPH_LP_CPU, SWID_PERIPH_ULP,
    SWID_PERIPH_MAX
} swid_peripheral_type_t;

/* Maximum v2 profile input: 18 header + 29 chip + 33 memory + 20 radio
 * bytes and at most one 15-byte TLV per declared peripheral type. */
#define SWID_FINGERPRINT_INPUT_MAX_BYTES (100u + 15u * SWID_PERIPH_MAX)

typedef struct {
    swid_peripheral_type_t type;
    uint8_t supported;
    uint8_t controller_count;
    uint16_t channel_count;
    uint32_t feature_flags;
    swid_status_t status;
    swid_evidence_t evidence;
} swid_peripheral_t;

typedef struct {
    swid_peripheral_t items[SWID_MAX_PERIPHERALS];
    size_t count;
    swid_status_t status;
    swid_evidence_t evidence;
} swid_peripheral_profile_t;

typedef struct {
    swid_chip_info_t chip;
    swid_identity_t identity;
    swid_memory_info_t memory;
    swid_radio_info_t radio;
    swid_peripheral_profile_t peripherals;
} swid_manifest_t;
