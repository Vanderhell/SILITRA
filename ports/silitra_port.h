/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Vanderhell */
#pragma once
#include "silitra_types.h"

silitra_err_t silitra_port_collect(silitra_manifest_t *out);
silitra_err_t silitra_port_hash256(const uint8_t *data, size_t len, uint8_t out[32]);
