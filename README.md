# SWID

SWID (Silicon & System Hardware Identity) is a fixed-storage C11 library for reading documented ESP32 hardware identity and capabilities. It produces deterministic SHA-256 fingerprints and a serialized hardware manifest. The library has no required heap allocation or Python dependency.

## Features

- Silicon, Assembly, and Hardware Profile fingerprints using fingerprint schema v2.
- Complete manifest serialization using manifest schema v1.
- ESP-IDF acquisition port and capability profile.
- Optional ROM/eFuse read-only and volatile RAM Probe host tools.

## Target status

- **Hardware verified:** ESP32-C3 and ESP32-S3 RAM Probe captures and flash readback integrity checks.
- **Build verified (ESP-IDF 5.5.1):** ESP32, ESP32-S2, ESP32-C2, ESP32-C5, ESP32-C6, ESP32-C61, ESP32-H2, ESP32-H21, ESP32-H4, and ESP32-P4 RAM Probe builds. Physical RAM loading has not been verified for these targets.
- Original application recovery was confirmed on the tested C3. It remains unverified on S3 in the latest validation. These results apply only to the tested device and software combinations.

## Use as an ESP-IDF component

Add this repository's `components/swid` directory to `EXTRA_COMPONENT_DIRS`, then require the `swid` component from the application component. The library API is declared in `include/swid.h`.

```c
#include "swid.h"

swid_manifest_t profile;
uint8_t silicon_fingerprint[32];

if (swid_init() == SWID_OK &&
    swid_get_manifest(&profile) == SWID_OK &&
    swid_get_fingerprint(SWID_FP_SILICON, silicon_fingerprint) == SWID_OK) {
    /* Use the manifest and 32-byte fingerprint. */
}
```

Silicon identifies MCU fields. Assembly additionally includes supported memory identity. Hardware Profile describes normalized hardware capabilities and may match across different devices.

## Build and test

The C library requires CMake, a C11 compiler, and ESP-IDF when building for an ESP32 target. Python is not required by the library.

```sh
cmake -S . -B build-host -DSWID_HOST_TESTS=ON
cmake --build build-host
ctest --test-dir build-host --output-on-failure
python -m unittest discover -s tests -v
```

For ESP-IDF 5.5.1, first export the ESP-IDF environment, then build the application for a target:

```sh
idf.py -B build-s3 set-target esp32s3
idf.py -B build-s3 build
```

## Optional host acquisition tools

The host tools require Python 3.10 or newer, `esptool` and `pyserial`. Install those optional tools with `python -m pip install -r requirements-tools.txt`. RAM Probe builds additionally require an exported ESP-IDF environment and its target toolchain.

```sh
python host/swid_nonflash.py --list
python host/swid_nonflash.py --mac <ROM-MAC> --mode auto
```

`auto` reads ROM/eFuse information and uses RAM Probe when a build-verified target adapter is available. `rom-only` and `ram-only` select acquisition paths explicitly. The optional `flash` mode reads an already-installed FP1 application for reference; it does not flash firmware. Full flash SHA-256 comparison is opt-in with `--verify-flash`.

## Limitations and safety

Optional Unique ID and flash Unique ID are not present on every part. Fingerprints over public identifiers are public identifiers, not secret keys or authentication evidence; hashing does not create secrecy or prove entropy. Capability declarations do not functionally test each peripheral. RAM Probe temporarily takes over execution and may be unavailable due to ROM access or device security settings. The core stores one module-level manifest, so callers must serialize initialization, getters, and fingerprint calculations against concurrent access.

## License

Apache-2.0. Copyright 2026 Vanderhell. See [LICENSE](LICENSE).
