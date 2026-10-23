# SWID

SWID (Silicon & System Hardware Identity) is a small C11 library for reading documented ESP32 hardware identity and capabilities and calculating deterministic SHA-256 fingerprints. Public identifiers are not secret keys or authentication.

## Implemented

- Fixed-storage C API for chip, identity, memory, radio, peripheral capabilities, manifest serialization, and Silicon, Assembly, and Hardware Profile fingerprints (schema v2).
- ESP-IDF acquisition port, read-only ROM/eFuse host inventory, and volatile RAM Probe.
- FP1 host campaign with read-only/RAM acquisition by default.

## Target verification

- ESP32-S3: ESP-IDF 5.5.1 RAM Probe build verified and physically RAM-loaded on two devices. Both completed 50-sample captures and 20 software-reset/reload checks; the size-optimized image also completed 50-sample captures on both.
- ESP32-C3, ESP32, ESP32-S2, ESP32-C2, ESP32-C5, ESP32-C6, ESP32-C61, ESP32-H2, ESP32-H21, ESP32-H4, and ESP32-P4: RAM Probe builds verified with ESP-IDF 5.5.1. Physical RAM loading has not been verified for these targets in this checkout.
- SoC capability fields absent from an ESP-IDF target's headers are reported as unknown where detected; build support does not imply physical validation.

## Build and test

With CMake and a C11 compiler:

```powershell
cmake -S . -B build-host -DSWID_HOST_TESTS=ON
cmake --build build-host
ctest --test-dir build-host -C Debug --output-on-failure
python -m unittest discover -s tests -v
```

With ESP-IDF 5.5.1 exported:

```powershell
idf.py -B build-s3 set-target esp32s3
idf.py -B build-s3 build
idf.py -B build-c3 set-target esp32c3
idf.py -B build-c3 build
```

Build the volatile probe with the configured ESP-IDF Python environment:

```powershell
python -c "from host.swid_nonflash import build_ram_probe; print(build_ram_probe('esp32s3'))"
python -c "from host.swid_nonflash import build_ram_probe; print(build_ram_probe('esp32c3'))"
```

## Read-only and RAM fingerprint acquisition

```powershell
python host/swid_nonflash.py --list
python host/swid_nonflash.py --mac 3C:0F:02:D9:76:F0 --mode auto
```

`auto` reads ROM/eFuse data and uses RAM Probe for targets with a declared build-verified adapter. `rom-only` and `ram-only` select those paths explicitly. No mode writes flash. `flash` reads the pre-existing FP1 application as an optional reference; it is not a flash-writing mode. Full flash SHA-256 comparison is separately opt-in with `--verify-flash` and may take several minutes.

RAM Probe builds default to size optimization and a 4096-byte main task stack. The optimized S3 image was 173920 bytes versus 190960 bytes with the earlier debug configuration; both physical devices retained identical fingerprint values and had 2340 free stack words at the measured high-water mark.

`swid_serialize_fingerprint_input()` encodes the stable fingerprint schema v2. `swid_serialize_manifest()` encodes the complete manifest using its separate schema v1; the two byte streams serve different purposes.

## C API

```c
#include "swid.h"

swid_manifest_t profile;
uint8_t silicon_fingerprint[32];

if (swid_init() == SWID_OK &&
    swid_get_manifest(&profile) == SWID_OK &&
    swid_get_fingerprint(SWID_FP_SILICON, silicon_fingerprint) == SWID_OK) {
    /* Use the profile and 32-byte fingerprint. */
}
```

Silicon identifies MCU fields. Assembly adds individually identifiable memory components when available. Hardware Profile describes normalized capabilities and may match across different devices.

## Limitations

Optional Unique ID and flash Unique ID are not guaranteed on every part. Fingerprints over public identifiers remain public, and hashing does not create secrecy or prove entropy. Capability declarations are not functional tests of every peripheral. RAM Probe temporarily takes over execution and may be unavailable when ROM access or device security settings prevent it. External components are included only when their identifiers are explicitly supported.
