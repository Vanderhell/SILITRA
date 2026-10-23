# SWID

SWID (Silicon & System Hardware Identity) v1.0.1 is a small C11 library for reading documented ESP32 hardware identity and capabilities and calculating deterministic SHA-256 fingerprints. Public identifiers are not secret keys or authentication.

## Implemented

- Fixed-storage C API for chip, identity, memory, radio, peripheral capabilities, manifest serialization, and Silicon, Assembly, and Hardware Profile fingerprints (schema v2).
- ESP-IDF acquisition port, read-only ROM/eFuse host inventory, and volatile RAM Probe.
- FP1 host campaign with read-only/RAM acquisition by default.

## Target verification

- ESP32-S3: ESP-IDF 5.5.1 RAM Probe build verified and physically RAM-loaded on two devices. Both completed 50-sample captures and 20 software-reset/reload checks; the size-optimized image also completed 50-sample captures on both. The currently attached rev 0.2 S3 passed 50 post-optimization samples and full-flash SHA-256 before/after; its original application recovery was not independently observable in this run.
- ESP32-C3: ESP-IDF 5.5.1 RAM Probe build and physical ROM RAM-load verified on MAC `34:B7:DA:F8:78:70` (rev 0.4, 4 MiB XMC flash). The three v2 fingerprints matched host/C canonical TLV and SHA-256. Before optimization, 1,000 repeated measurements across 20 software resets were stable; after optimization, 50 samples passed with a 4 KiB main stack and identical fingerprints. Full-flash read-only SHA-256 matched before and after, and the original app recovered with a valid FP1 response.
- ESP32, ESP32-S2, ESP32-C2, ESP32-C5, ESP32-C6, ESP32-C61, ESP32-H2, ESP32-H21, ESP32-H4, and ESP32-P4: RAM Probe builds verified with ESP-IDF 5.5.1. Physical RAM loading has not been verified for these targets in this checkout.
- SoC capability fields absent from an ESP-IDF target's headers are reported as unknown where detected; build support does not imply physical validation.

On the two previously tested ESP32-S3 devices, read-only full-flash SHA-256 matched before and after RAM Probe, and each original application's observable boot markers returned after reset. The C3 and currently attached S3 also had matching full-flash hashes before and after; only C3 recovery was independently confirmed in the latest run. This evidence is limited to the tested device/application combinations and does not guarantee behavior on other hardware or security configurations. Other targets' flash integrity and application recovery are unverified.

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

RAM Probe builds default to size optimization with a 4,096-byte main task stack. The v1.0.0 C3 fingerprint function allocated 4,128 bytes for a fixed-size TLV buffer before nested serializer and SHA frames, which caused a stack-protection fault on C3. The v1.0.1 core derives a 610-byte schema-v2 upper bound and uses a 640-byte stack frame. On the tested C3, 2,152 bytes of the 4,096-byte stack remained at high-water mark; on the tested S3, 1,700 bytes remained. The production C3/S3 images were 143,360/174,080 bytes. A separate `profile` RAM Probe build emits 16-sample min/median/max timings and is larger; it is not the default acquisition image.

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

Optional Unique ID and flash Unique ID are not guaranteed on every part. Fingerprints over public identifiers remain public; they are neither secret keys nor authentication evidence, and hashing does not create secrecy or prove entropy. Capability declarations are not functional tests of every peripheral. RAM Probe temporarily takes over execution and may be unavailable when ROM access or device security settings prevent it. External components are included only when their identifiers are explicitly supported.

The core keeps one module-level manifest. Callers must serialize `swid_init()`, getters and fingerprint calculations against concurrent access. The explicit manifest/fingerprint serializers can be called concurrently when each call uses separate buffers.
