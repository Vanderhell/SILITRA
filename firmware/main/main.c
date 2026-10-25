/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#include "swid.h"

#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/usb_serial_jtag.h"
#include "driver/uart.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FP1_LINE_CAPACITY 256u
#define FP1_PAYLOAD_CAPACITY 1900u

static void transport_write(const char *data, size_t length) {
#ifdef SWID_FP1_UART_TRANSPORT
    (void)uart_write_bytes(UART_NUM_0, data, length);
    (void)uart_wait_tx_done(UART_NUM_0, pdMS_TO_TICKS(1000));
#else
    (void)usb_serial_jtag_write_bytes(data, length, pdMS_TO_TICKS(1000));
    (void)usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(1000));
#endif
}

static int transport_read(uint8_t *byte) {
#ifdef SWID_FP1_UART_TRANSPORT
    return uart_read_bytes(UART_NUM_0, byte, 1, pdMS_TO_TICKS(250));
#else
    return usb_serial_jtag_read_bytes(byte, 1, pdMS_TO_TICKS(250));
#endif
}

static uint32_t crc32(const char *data, size_t length) {
    uint32_t value = UINT32_C(0xFFFFFFFF);
    for (size_t i = 0; i < length; ++i) {
        value ^= (uint8_t)data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            value = (value >> 1) ^ (UINT32_C(0xEDB88320) & (uint32_t)-(int32_t)(value & 1u));
    }
    return ~value;
}

static void send_frame(const char *request_id, const char *kind, const char *payload) {
    char body[FP1_PAYLOAD_CAPACITY + 128];
    char frame[FP1_PAYLOAD_CAPACITY + 144];
    const int body_length = snprintf(body, sizeof(body), "FP1|%s|%s|%u|%s",
                                     request_id, kind, (unsigned)strlen(payload), payload);
    if (body_length < 0 || (size_t)body_length >= sizeof(body)) return;
    const int frame_length = snprintf(frame, sizeof(frame), "%s|%08" PRIX32 "\n",
                                      body, crc32(body, (size_t)body_length));
    if (frame_length > 0 && (size_t)frame_length < sizeof(frame))
        transport_write(frame, (size_t)frame_length);
}

static void hex_encode(const uint8_t *data, size_t length, char *out) {
    static const char digits[] = "0123456789ABCDEF";
    for (size_t i = 0; i < length; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 0x0Fu];
    }
    out[2 * length] = '\0';
}

static void send_profile(const char *request_id) {
    swid_manifest_t manifest;
    uint8_t digests[3][32];
    char hashes[3][65];
    static const swid_fingerprint_kind_t kinds[] = {
        SWID_FP_SILICON, SWID_FP_ASSEMBLY, SWID_FP_PROFILE
    };
    if (swid_get_manifest(&manifest) != SWID_OK) {
        send_frame(request_id, "swid_profile", "{\"valid\":false}");
        return;
    }
    for (size_t i = 0; i < 3; ++i) {
        if (swid_get_fingerprint(kinds[i], digests[i]) != SWID_OK) {
            send_frame(request_id, "swid_profile", "{\"valid\":false}");
            return;
        }
        hex_encode(digests[i], sizeof(digests[i]), hashes[i]);
    }
    char payload[600];
    (void)snprintf(payload, sizeof(payload),
        "{\"valid\":true,\"schema\":%u,\"chip_model\":%u,\"revision\":%u,"
        "\"cores\":%u,\"reset_reason\":%d,\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
        "\"optional_uid_valid\":%s,\"flash_jedec\":\"%06" PRIX32 "\","
        "\"flash_unique_id_valid\":%s,\"flash_capacity\":%" PRIu32 ","
        "\"psram_capacity\":%" PRIu32 ",\"peripheral_count\":%u,"
        "\"silicon_fingerprint\":\"%s\",\"assembly_fingerprint\":\"%s\","
        "\"profile_fingerprint\":\"%s\"}",
        SWID_SCHEMA_VERSION, manifest.chip.model, manifest.chip.revision, manifest.chip.cores,
        (int)esp_reset_reason(), manifest.identity.base_mac[0], manifest.identity.base_mac[1],
        manifest.identity.base_mac[2], manifest.identity.base_mac[3], manifest.identity.base_mac[4],
        manifest.identity.base_mac[5], manifest.identity.optional_uid_valid ? "true" : "false",
        manifest.memory.flash_jedec_id,
        manifest.memory.flash_unique_id_valid ? "true" : "false",
        manifest.memory.flash_capacity_bytes, manifest.memory.psram_capacity_bytes,
        (unsigned)manifest.peripherals.count, hashes[0], hashes[1], hashes[2]);
    send_frame(request_id, "swid_profile", payload);
}

static void send_tlv(const char *request_id, const char *name) {
    swid_fingerprint_kind_t kind;
    if (strcmp(name, "silicon") == 0) kind = SWID_FP_SILICON;
    else if (strcmp(name, "assembly") == 0) kind = SWID_FP_ASSEMBLY;
    else if (strcmp(name, "profile") == 0) kind = SWID_FP_PROFILE;
    else {
        send_frame(request_id, "swid_tlv", "{\"valid\":false,\"error\":\"unknown_kind\"}");
        return;
    }
    swid_manifest_t manifest;
    uint8_t encoded[1024];
    char hex[2049];
    size_t length = 0;
    if (swid_get_manifest(&manifest) != SWID_OK ||
        swid_serialize_fingerprint_input(&manifest, kind, encoded, sizeof(encoded), &length) != SWID_OK ||
        length * 2 >= sizeof(hex)) {
        send_frame(request_id, "swid_tlv", "{\"valid\":false,\"error\":\"serialization_failed\"}");
        return;
    }
    hex_encode(encoded, length, hex);
    char payload[2200];
    (void)snprintf(payload, sizeof(payload),
                   "{\"valid\":true,\"schema\":%u,\"kind\":\"%s\","
                   "\"length\":%u,\"tlv_hex\":\"%s\"}",
                   SWID_SCHEMA_VERSION, name, (unsigned)length, hex);
    send_frame(request_id, "swid_tlv", payload);
}

static void handle_frame(char *line) {
    char *crc_separator = strrchr(line, '|');
    if (!crc_separator || strlen(crc_separator + 1) != 8) return;
    char *crc_end = NULL;
    const unsigned long received_crc = strtoul(crc_separator + 1, &crc_end, 16);
    if (!crc_end || *crc_end != '\0' ||
        received_crc != crc32(line, (size_t)(crc_separator - line))) return;
    *crc_separator = '\0';
    if (strncmp(line, "FP1|", 4) != 0) return;

    char *request_id = line + 4;
    char *separator = strchr(request_id, '|');
    if (!separator) return;
    *separator++ = '\0';
    char *command = separator;
    separator = strchr(command, '|');
    if (!separator) return;
    *separator++ = '\0';
    char *length_text = separator;
    separator = strchr(length_text, '|');
    if (!separator) return;
    *separator++ = '\0';
    char *payload = separator;
    char *length_end = NULL;
    const unsigned long declared = strtoul(length_text, &length_end, 10);
    if (!length_end || *length_end != '\0' || declared != strlen(payload)) return;

    if (strcmp(command, "ping") == 0) {
        send_frame(request_id, "pong", "{\"type\":\"pong\"}");
    } else if (strcmp(command, "swid_profile") == 0) {
        send_profile(request_id);
    } else if (strcmp(command, "swid_tlv") == 0) {
        send_tlv(request_id, payload);
    } else if (strcmp(command, "software_reset") == 0) {
        send_frame(request_id, "software_reset", "{\"accepted\":true,\"method\":\"esp_restart\"}");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        send_frame(request_id, "error", "{\"error\":\"unknown_command\"}");
    }
}

static void command_loop(void) {
    char line[FP1_LINE_CAPACITY];
    size_t length = 0;
    for (;;) {
        uint8_t byte;
        if (transport_read(&byte) <= 0) continue;
        if (byte != '\r' && byte != '\n') {
            if (length < sizeof(line) - 1) line[length++] = (char)byte;
            else length = 0;
            continue;
        }
        if (!length) continue;
        line[length] = '\0';
        handle_frame(line);
        length = 0;
    }
}

void app_main(void) {
    const swid_err_t status = swid_init();
#ifdef SWID_FP1_UART_TRANSPORT
    const uart_config_t config = {
        .baud_rate = 115200, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1, .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    (void)uart_driver_install(UART_NUM_0, 2048, 2048, 0, NULL, 0);
    (void)uart_param_config(UART_NUM_0, &config);
#else
    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 2048;
        config.rx_buffer_size = 1024;
        (void)usb_serial_jtag_driver_install(&config);
    }
#endif
    printf("{\"type\":\"swid\",\"schema\":%u,\"init_status\":%d}\n",
           SWID_SCHEMA_VERSION, (int)status);
    printf("{\"type\":\"ready\",\"commands\":\"ping|swid_profile|swid_tlv|software_reset\"}\n");
    fflush(stdout);
    command_loop();
}
