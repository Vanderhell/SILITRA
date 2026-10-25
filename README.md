# SILITRA

SILITRA (Silicon Identity & Traceability) is an embedded C11 hardware identity library for Espressif ESP32 MCUs. It reads documented device and memory properties, exposes a stable manifest, and calculates deterministic SHA-256 fingerprints without mandatory heap allocation.

Current release: `v2.0.1`.

## Features

- Silicon, Assembly, and Hardware Profile fingerprints.
- Fingerprint schema v2 and manifest schema v1.
- ESP-IDF acquisition component and optional ROM/eFuse plus RAM-only host tools.
- SWID v1.0.1 compatibility headers and exported wrapper symbols.

The rebrand preserves the historical `SWID` TLV magic, field identifiers, canonical byte encoding, fingerprint outputs, and FP1 commands. New applications should use the `silitra_*` API. Existing source and binary clients can continue using the deprecated `swid_*` API.

## Target support

ESP32-C3 and ESP32-S3 have physical RAM Probe validation. ESP32, ESP32-S2, ESP32-C2, ESP32-C5, ESP32-C6, ESP32-C61, ESP32-H2, ESP32-H21, ESP32-H4, and ESP32-P4 are build-verified only; they have not all been physically tested. These statuses reflect the validated ESP-IDF 5.5.1 toolchain and do not imply support by every ESP-IDF release.

## ESP-IDF integration

Add this repository's `components` directory to `EXTRA_COMPONENT_DIRS`, then add `silitra` to the application's `REQUIRES` list.

```c
#include "silitra.h"

silitra_manifest_t manifest;
uint8_t silicon_fingerprint[32];

if (silitra_init() == SILITRA_OK &&
    silitra_get_manifest(&manifest) == SILITRA_OK &&
    silitra_get_fingerprint(SILITRA_FP_SILICON, silicon_fingerprint) == SILITRA_OK) {
    /* Use the manifest and 32-byte fingerprint. */
}
```

The Silicon fingerprint describes MCU identity inputs. Assembly also includes supported memory identity. Hardware Profile represents normalized chip and capability properties and can be identical across devices. Fingerprints are identifiers, not secret keys or authentication proofs.

## Host acquisition

The C library does not require Python. Optional host tools require Python 3.10+, `esptool`, and `pyserial`; install them with `python -m pip install -r requirements-tools.txt`.

```sh
python host/silitra.py --list
python host/silitra.py --mac <ROM-MAC> --mode auto
```

`auto` performs ROM/eFuse reads and uses a supported volatile RAM Probe. `rom-only` and `ram-only` select those acquisition paths. No mode automatically flashes firmware. The optional FP1 mode reads an already-installed application as a reference; it does not flash.

## Build and test

```sh
cmake -S . -B build-host -DSILITRA_HOST_TESTS=ON
cmake --build build-host
ctest --test-dir build-host --output-on-failure
python -m unittest discover -s tests -v
```

For ESP-IDF builds, export the ESP-IDF environment first, then use `idf.py -B build-s3 set-target esp32s3` and `idf.py -B build-s3 build` (or `esp32c3`).

## Limitations

Optional Unique ID and flash Unique ID are not available on every part. Public identifiers remain public after hashing. Capability declarations do not functionally test every peripheral. RAM Probe temporarily takes over device execution and may be unavailable because of ROM, target, or device security restrictions. Original application recovery was confirmed on a tested C3; it remains unverified on S3 in the latest validation.

## License

Apache-2.0. Copyright 2026 Vanderhell. See [LICENSE](LICENSE).
