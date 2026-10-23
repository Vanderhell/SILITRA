# SWID

SWID (Silicon & System Hardware Identity) is a small C11 library for reading documented ESP32 hardware identity and capabilities and calculating deterministic SHA-256 fingerprints. Public identifiers are not secret keys or authentication.

## Implemented

- Fixed-storage C API for chip, identity, memory, radio, peripheral capabilities, manifest serialization, and Silicon, Assembly, and Hardware Profile fingerprints (schema v2).
- ESP-IDF acquisition port, read-only ROM/eFuse host inventory, and volatile RAM Probe.
- FP1 host campaign with read-only/RAM acquisition by default.

## Target verification

- ESP32-S3: build verified; RAM Probe and SWID firmware have prior physical verification.
- ESP32-C3: build verified; no physical RAM Probe verification is included here.
- Other ESP32 targets: not implemented by the current ESP-IDF adapter.

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
python host/swid_nonflash.py --port COM4 --mac 02:00:00:00:00:01 --mode auto
```

`auto` reads ROM/eFuse data and uses RAM Probe only for build-verified targets. `rom-only` and `ram-only` select those paths explicitly. Flash acquisition is a separate explicit mode; it is not the default.

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
