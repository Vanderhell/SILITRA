#pragma once
#include "swid_types.h"

swid_err_t swid_port_collect(swid_manifest_t *out);
swid_err_t swid_port_hash256(const uint8_t *data, size_t len, uint8_t out[32]);
