"""Read-only ROM/eFuse inventory and RAM-only SWID v2 capture helpers."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import os
import shutil
import subprocess
import sys
import tempfile
import time

try:
    from serial.tools import list_ports
except ImportError:  # Host unit tests can exercise serialization without pyserial.
    list_ports = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "swid_nonflash_research"
PYTHON = pathlib.Path(os.environ.get("SWID_PYTHON", r"C:\Espressif\tools\python\v5.5.1\venv\Scripts\python.exe"))
IDF_RAM_CANDIDATES = {
    "esp32", "esp32s2", "esp32s3", "esp32c2", "esp32c3", "esp32c5",
    "esp32c6", "esp32c61", "esp32h2", "esp32h21", "esp32h4", "esp32p4",
}
RAM_PROBE_BUILD_VERIFIED_TARGETS = set(IDF_RAM_CANDIDATES)


def tlv(field: int, value: bytes) -> bytes:
    if not 0 <= field <= 255 or len(value) > 0xFFFF:
        raise ValueError("TLV field id/length out of range")
    return bytes((field, len(value) & 0xFF, len(value) >> 8)) + value


def le(value: int, width: int) -> bytes:
    if not 0 <= value < 1 << (width * 8):
        raise ValueError("integer does not fit schema width")
    return value.to_bytes(width, "little")


def serialize_v2(manifest: dict, kind: str) -> bytes:
    """Byte-for-byte equivalent to src/swid_core.c serialize_kind()."""
    kinds = {"silicon": 1, "assembly": 2, "profile": 3}
    if kind not in kinds:
        raise ValueError("unknown fingerprint kind")
    out = tlv(1, b"SWID") + tlv(2, le(2, 4)) + tlv(3, bytes((kinds[kind],)))
    chip = manifest["chip"]
    out += tlv(10, le(chip["family"], 2)) + tlv(11, le(chip["model"], 2))
    out += tlv(12, bytes((chip["revision"],))) + tlv(13, bytes((chip["cores"],)))
    out += tlv(14, bytes((chip["package"],))) + tlv(15, le(chip["features"], 4))
    identity, memory = manifest["identity"], manifest["memory"]
    if kind in {"silicon", "assembly"}:
        mac = bytes.fromhex(identity["mac"].replace(":", "")) if identity.get("mac_valid") else b""
        optional = bytes.fromhex(identity["optional_uid"]) if identity.get("optional_uid_valid") else b""
        out += tlv(20, mac) + tlv(21, optional)
    if kind in {"assembly", "profile"}:
        out += tlv(30, le(memory["flash_jedec"], 4))
        out += tlv(31, le(memory["flash_capacity_bytes"], 4))
        out += tlv(32, le(memory["psram_capacity_bytes"], 4))
        out += tlv(33, bytes((int(memory["psram_present"]),)))
        out += tlv(34, bytes((memory["psram_interface"],)))
        out += tlv(35, bytes((memory["psram_location"],)))
    if kind == "assembly":
        uid = int(memory["flash_unique_id"], 16).to_bytes(8, "little") if memory.get("flash_unique_id_valid") else b""
        out += tlv(36, uid)
    if kind == "profile":
        radio = manifest["radio"]
        for field, key in zip(range(40, 45), ("wifi_supported", "wifi_generation", "bluetooth_supported", "ble_supported", "bt_classic_supported")):
            out += tlv(field, bytes((radio[key],)))
        items = sorted(manifest["peripherals"], key=lambda item: item["type"])
        for item in items:
            encoded = (bytes((item["type"], item["supported"], item["controllers"]))
                       + le(item["channels"], 2) + bytes((item["status"], item["evidence"]))
                       + le(item["feature_flags"], 4) + b"\0")
            out += tlv(50, encoded)
    return out


def fingerprint(manifest: dict, kind: str) -> tuple[bytes, str]:
    data = serialize_v2(manifest, kind)
    return data, hashlib.sha256(data).hexdigest().upper()


def run_tool(*args: str, timeout: int = 90) -> str:
    env_python = os.environ.get("IDF_PYTHON_ENV_PATH")
    candidates = ([pathlib.Path(env_python) / "Scripts" / "python.exe"] if env_python else [])
    tools_root = pathlib.Path(os.environ.get("IDF_TOOLS_PATH", r"C:\Espressif\tools"))
    candidates += [PYTHON, tools_root / "python" / "v5.5.1" / "venv" / "Scripts" / "python.exe",
                   pathlib.Path(sys.executable)]
    python = next((p for p in candidates if p.exists()), pathlib.Path(sys.executable))
    proc = subprocess.run([str(python), *args], cwd=ROOT, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"read-only tool failed ({proc.returncode}): {' '.join(args)}\n{proc.stdout}")
    return proc.stdout


SAFE_EFUSE_FIELDS = {
    "MAC", "OPTIONAL_UNIQUE_ID", "CHIP_VER_REV1", "CHIP_VER_REV2", "CHIP_VER_REV3",
    "CHIP_VER_PKG", "PKG_VERSION", "WAFER_VERSION_MAJOR", "WAFER_VERSION_MINOR",
    "WAFER_VERSION_MINOR_HI", "WAFER_VERSION_MINOR_LO", "BLK_VERSION_MAJOR", "BLK_VERSION_MINOR",
    "FLASH_CAP", "FLASH_TYPE", "FLASH_VENDOR", "PSRAM_CAP", "PSRAM_CAPACITY", "PSRAM_VENDOR",
    "PSRAM_CAP_3",
    "SECURE_BOOT_EN", "SPI_BOOT_CRYPT_CNT", "RD_DIS", "WR_DIS", "DIS_PAD_JTAG",
    "SOFT_DIS_JTAG", "DIS_USB_JTAG", "DIS_USB_SERIAL_JTAG", "DIS_USB_OTG",
    "SECURE_VERSION", "UART_PRINT_CONTROL", "OCODE", "TEMP_CALIB",
    *(f"KEY_PURPOSE_{i}" for i in range(6)),
    *(f"ADC{unit}_{prefix}_ATTEN{atten}" for unit in (1, 2)
      for prefix in ("CAL_VOL", "INIT_CODE") for atten in range(4)),
}
# This target-stable query deliberately omits every KEY/BLOCK payload. The
# requested key-purpose and read-protection metadata is not secret key content.
SAFE_EFUSE_QUERY = ["MAC", "OPTIONAL_UNIQUE_ID", "PKG_VERSION", "SECURE_BOOT_EN",
                    "SPI_BOOT_CRYPT_CNT", "RD_DIS", "WR_DIS", "TEMP_CALIB",
                    "ADC1_INIT_CODE_ATTEN0", "ADC1_CAL_VOL_ATTEN0",
                    *(f"KEY_PURPOSE_{i}" for i in range(6))]


def parse_safe_efuse_summary(text: str) -> dict:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("espefuse did not return JSON summary")
    data = json.loads(text[start:end + 1])
    safe = {}
    for name, item in data.items():
        if name not in SAFE_EFUSE_FIELDS or not isinstance(item, dict):
            continue
        # Never preserve raw bit words or key-block bytes. Key purpose/protection
        # metadata is useful, but block contents are intentionally excluded.
        safe[name] = {k: item[k] for k in ("name", "bit_len", "block", "category", "description", "readable", "writeable", "value") if k in item}
    return safe


def candidates() -> list[dict]:
    if list_ports is None:
        raise RuntimeError("pyserial is required for USB discovery")
    return [{"port": p.device, "vid": p.vid, "pid": p.pid,
             "usb_serial": p.serial_number, "description": p.description}
            for p in list_ports.comports() if p.vid is not None]


def resolve_enumerated_port(mac: str, preferred_port: str | None = None,
                            attempts: int = 40, delay: float = 0.25) -> str:
    """Wait for USB re-enumeration and prefer the adapter serial matching ROM MAC."""
    expected = mac.replace(":", "").replace("-", "").upper()
    for _ in range(attempts):
        devices = candidates()
        for item in devices:
            serial = (item.get("usb_serial") or "").replace(":", "").replace("-", "").upper()
            if serial == expected:
                return item["port"]
        if preferred_port and any(item["port"] == preferred_port for item in devices):
            return preferred_port
        time.sleep(delay)
    raise TimeoutError(f"USB serial interface for {mac} did not re-enumerate")


def identify(port: str) -> dict:
    raw = run_tool("-m", "esptool", "--port", port, "--baud", "460800", "chip_id", timeout=45)
    mac = re.search(r"MAC:\s*([0-9a-f:]{17})", raw, re.I)
    chip = re.search(r"Chip is (ESP32(?:-[A-Z0-9]+)?) \(([^)]+)\) \(revision v([0-9.]+)\)", raw, re.I)
    features = re.search(r"Features:\s*(.*)", raw)
    if not mac or not chip:
        raise RuntimeError(f"Could not parse ROM identity from {port}: {raw}")
    return {"port": port, "mac": mac.group(1).upper(), "model": chip.group(1).upper(),
            "package_description": chip.group(2), "revision": chip.group(3),
            "rom_features_text": features.group(1).strip() if features else None,
            "rom_output_sha256": hashlib.sha256(raw.encode()).hexdigest().upper(),
            "evidence": "ROM_READ"}


def identify_expected_device(mac: str, preferred_port: str | None = None,
                             target: str | None = None, attempts: int = 8) -> dict:
    """Resolve USB re-enumeration by ROM MAC, never by a remembered COM name alone."""
    last_error = None
    for _ in range(attempts):
        devices = candidates()
        expected = mac.replace(":", "").replace("-", "").upper()
        serial_match = [item["port"] for item in devices
                        if (item.get("usb_serial") or "").replace(":", "").replace("-", "").upper() == expected]
        ports = [item["port"] for item in devices]
        ordered = serial_match + ([preferred_port] if preferred_port in ports and preferred_port not in serial_match else [])
        ordered += [p for p in ports if p not in ordered]
        for port in ordered:
            try:
                result = identify(port)
            except (RuntimeError, OSError, TimeoutError) as exc:
                last_error = str(exc)
                continue
            if result["mac"].upper() != mac.upper():
                last_error = f"{port} identifies as {result['mac']}, expected {mac}"
                continue
            if target and result["model"].lower().replace("-", "") != target.lower().replace("-", ""):
                raise RuntimeError(f"ROM target changed on {mac}: {result['model']} != {target}")
            return result
        time.sleep(0.5)
    raise RuntimeError(f"could not rediscover {mac} after USB re-enumeration: {last_error or 'no candidate ports'}")


def discover_rom_devices() -> list[dict]:
    """Identify serial candidates by ROM MAC and return unique ESP32 devices."""
    found = {}
    for item in candidates():
        try:
            result = identify(item["port"])
        except (RuntimeError, OSError, TimeoutError):
            continue
        found[result["mac"].upper()] = result
    return list(found.values())


def select_backend(mode: str, target: str) -> str:
    aliases = {"rom": "rom-only", "ram": "ram-only"}
    mode = aliases.get(mode, mode)
    if mode not in {"auto", "rom-only", "ram-only", "flash"}:
        raise ValueError("unknown backend mode")
    if mode != "auto":
        return mode
    normalized = target.lower().replace("-", "")
    return "ram-only" if normalized in RAM_PROBE_BUILD_VERIFIED_TARGETS else "rom-only"


def read_only_rom_inventory(port: str, expected_mac: str | None = None) -> dict:
    started = time.perf_counter()
    ident = identify(port)
    if expected_mac and ident["mac"] != expected_mac.upper():
        raise RuntimeError(f"MAC mismatch: expected {expected_mac}, got {ident['mac']}; no more commands issued")
    target = ident["model"].lower().replace("-", "")
    flash_error = None
    try:
        flash_text = run_tool("-m", "esptool", "--chip", target, "--port", port,
                              "--baud", "460800", "flash_id", timeout=60)
    except RuntimeError as exc:
        flash_text = ""
        flash_error = str(exc)
    manufacturer_match = re.search(r"(?m)^Manufacturer:\s*(?:0x)?([0-9a-f]+)\s*$", flash_text, re.I)
    device_match = re.search(r"(?m)^Device:\s*(?:0x)?([0-9a-f]+)\s*$", flash_text, re.I)
    size_match = re.search(r"Detected flash size:\s*(\d+)\s*MB", flash_text, re.I)
    efuse_error = None
    try:
        safe_summary = run_tool("-m", "espefuse", "--chip", target, "--port", port,
                                "summary", "--format", "json", *SAFE_EFUSE_QUERY,
                                *( ["FLASH_CAP", "FLASH_TYPE", "FLASH_VENDOR", "PSRAM_CAP", "PSRAM_VENDOR", "PSRAM_CAP_3", "PSRAM_CAPACITY"] if target == "esp32s3" else []),
                                timeout=60)
        safe_fields = parse_safe_efuse_summary(safe_summary)
    except (RuntimeError, ValueError) as exc:
        # ROM and flash identity remain useful when this esptool/espefuse
        # release does not know a target field or cannot query eFuses.
        safe_summary = ""
        safe_fields = {}
        efuse_error = str(exc)
    mac_field = safe_fields.get("MAC", {}).get("value")
    optional_field = safe_fields.get("OPTIONAL_UNIQUE_ID", {}).get("value")
    if isinstance(mac_field, str):
        mac_match = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", mac_field, re.I)
        if mac_match and mac_match.group(1).upper() != ident["mac"]:
            raise RuntimeError("ROM and eFuse MAC disagree")
    return {"schema": 1, "identity": ident,
            "flash": {"raw_evidence_sha256": hashlib.sha256(flash_text.encode()).hexdigest().upper() if flash_text else None,
                      "jedec_manufacturer": int(manufacturer_match.group(1), 16) if manufacturer_match else None,
                      "jedec_device": int(device_match.group(1), 16) if device_match else None,
                      "jedec_id": ((int(manufacturer_match.group(1), 16) << 16) | int(device_match.group(1), 16)) if manufacturer_match and device_match else None,
                      "capacity_bytes_reported": int(size_match.group(1)) * 1024 * 1024 if size_match else None,
                      "evidence": "ROM_FLASH_ID" if flash_text else "UNAVAILABLE",
                      "error": flash_error},
            "psram_rom_feature": re.search(r"Embedded PSRAM\s+([0-9]+\s*[KMG]B(?:\s+\([^)]*\))?)", ident.get("rom_features_text") or "", re.I).group(1) if re.search(r"Embedded PSRAM\s+([0-9]+\s*[KMG]B(?:\s+\([^)]*\))?)", ident.get("rom_features_text") or "", re.I) else None,
            "identity_fields": {"optional_unique_id": optional_field,
                                "optional_unique_id_available": optional_field not in (None, "", 0, "0"),
                                "package_version": safe_fields.get("PKG_VERSION", {}).get("value"),
                                "factory_mac": ident["mac"]},
            "efuse_summary": {"raw_not_persisted": True,
                              "safe_fields": safe_fields,
                              "output_sha256": hashlib.sha256(safe_summary.encode()).hexdigest().upper() if safe_summary else None,
                              "parsed": bool(safe_summary), "error": efuse_error,
                              "excluded": "raw efuse words, key blocks, key digests, and secret payloads"},
            "completeness": "PARTIAL", "fingerprints": {k: "UNAVAILABLE" for k in ("silicon", "assembly", "profile")},
            "elapsed_seconds": time.perf_counter() - started,
            "write_operations_attempted": [], "flash_write_attempted": False, "efuse_write_attempted": False}


def build_ram_probe(target: str, repeat_count: int = 50,
                    restart_after_capture: bool = True,
                    profile: str = "size") -> dict:
    target = target.lower().replace("-", "")
    if target not in IDF_RAM_CANDIDATES:
        raise RuntimeError(f"RAM probe has no declared ESP-IDF target adapter: {target}")
    if not 1 <= repeat_count <= 100:
        raise ValueError("RAM probe repeat_count must be in 1..100")
    if profile not in {"default", "size"}:
        raise ValueError("RAM probe profile must be default or size")
    idf = pathlib.Path(os.environ.get("SWID_IDF_PATH", os.environ.get("IDF_PATH", r"C:\esp\v5.5.1\esp-idf")))
    tools = pathlib.Path(os.environ.get("IDF_TOOLS_PATH", r"C:\Espressif\tools"))
    if not (idf / "tools" / "cmake" / "project.cmake").is_file():
        raise RuntimeError(f"ESP-IDF source tree not found: {idf}")

    def locate_executable(name: str, fallbacks: tuple[pathlib.Path, ...]) -> pathlib.Path:
        found = shutil.which(name)
        if found:
            return pathlib.Path(found)
        return next((candidate for candidate in fallbacks if candidate.is_file()), pathlib.Path(name))

    ninja = locate_executable("ninja", (tools / "ninja" / "1.12.1" / "ninja.exe",
        pathlib.Path(r"C:\Users\vande\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe\ninja.exe")))
    cmake = locate_executable("cmake", (pathlib.Path(r"C:\Program Files\CMake\bin\cmake.exe"),))
    idf_tools_python = pathlib.Path(os.environ.get("IDF_PYTHON_ENV_PATH", str(tools / "python" / "v5.5.1" / "venv")))
    python = next((p for p in (idf_tools_python / "Scripts" / "python.exe", PYTHON,
                               pathlib.Path(sys.executable)) if p.is_file()), pathlib.Path(sys.executable))
    # Keep probe builds separate from legacy experiment caches whose CMake
    # source path points at the pre-consolidation experiments/ tree.
    build_name = target.removeprefix("esp32") or "classic"
    build = ROOT / "build_probe" / "ram" / (build_name if profile == "default" else f"{build_name}-{profile}")
    sdkconfig = build / "sdkconfig.nonflash"
    env = dict(os.environ)
    env.update({"IDF_PATH": str(idf), "IDF_TOOLS_PATH": str(tools),
                "IDF_PYTHON_ENV_PATH": str(idf_tools_python)})
    riscv_arch = {
        "esp32c2": ("rv32imc_zicsr_zifencei", "ilp32"),
        "esp32c3": ("rv32imc_zicsr_zifencei", "ilp32"),
        "esp32c5": ("rv32imac_zicsr_zifencei", "ilp32"),
        "esp32c6": ("rv32imac_zicsr_zifencei", "ilp32"),
        "esp32c61": ("rv32imac_zicsr_zifencei", "ilp32"),
        "esp32h2": ("rv32imac_zicsr_zifencei", "ilp32"),
        "esp32h21": ("rv32imac_zicsr_zifencei", "ilp32"),
        "esp32h4": ("rv32imafc_zicsr_zifencei", "ilp32f"),
        "esp32p4": ("rv32imafc_zicsr_zifencei", "ilp32f"),
    }
    riscv_targets = set(riscv_arch)
    toolchain = "riscv32-esp-elf" if target in riscv_targets else "xtensa-esp-elf"
    compiler_name = "riscv32-esp-elf-gcc.exe" if toolchain.startswith("riscv") else f"xtensa-{target}-elf-gcc.exe"
    roots = (ROOT / ".espressif" / "tools", tools)
    bin_dir = next((candidate for root in roots
                    for candidate in root.glob(f"{toolchain}/*/{toolchain}/bin")
                    if (candidate / compiler_name).is_file()), None)
    if bin_dir is None:
        raise RuntimeError(f"ESP-IDF compiler {compiler_name} not found for {target}; checked {roots}")
    env["PATH"] = str(python.parent) + ";" + str(bin_dir) + ";" + env.get("PATH", "")
    probe_project = ROOT / "probes" / "ram"
    defaults = str(probe_project / "sdkconfig.defaults")
    if profile == "size":
        defaults += ";" + str(probe_project / "sdkconfig.defaults.size")
    if target == "esp32s3":
        defaults += ";" + str(probe_project / "sdkconfig.defaults.esp32s3")
    args = [str(cmake), "-G", "Ninja", "-S", str(probe_project), "-B", str(build),
            f"-DIDF_TARGET={target}", f"-DSDKCONFIG={sdkconfig}",
            f"-DSDKCONFIG_DEFAULTS={defaults}",
              f"-DCMAKE_C_FLAGS=-DSWID_RAM_PROBE_REPEAT_COUNT={repeat_count} -DSWID_RAM_PROBE_RESTART_AFTER_CAPTURE={1 if restart_after_capture else 0}",
              f"-DPYTHON={python}"]
    if target in riscv_arch:
        toolchain_file = idf / "tools" / "cmake" / f"toolchain-{target}.cmake"
        flags = toolchain_file.read_text(encoding="utf-8") if toolchain_file.is_file() else ""
        march_match = re.search(r"-march=([^\s\"]+)", flags)
        abi_match = re.search(r"-mabi=([^\s\"]+)", flags)
        arch, abi = riscv_arch[target]
        if march_match:
            arch = march_match.group(1)
            abi = abi_match.group(1) if abi_match else abi
        compiler_root = bin_dir.parent / "riscv32-esp-elf"
        cxx_root = compiler_root / "include" / "c++"
        version_root = next(iter(sorted(cxx_root.glob("*"), reverse=True)), None)
        arch_root = (version_root / "riscv32-esp-elf") if version_root else pathlib.Path()
        arch_dir = next((p for p in arch_root.iterdir() if p.is_dir() and arch.startswith(p.name)), None) if arch_root.is_dir() else None
        if arch_dir is None:
            raise RuntimeError(f"RISC-V C++ architecture headers not found for -march={arch}")
        cxx_include = arch_dir / abi / "no-rtti"
        if not cxx_include.is_dir():
            raise RuntimeError(f"RISC-V C++ target headers are unavailable: {cxx_include}")
        args.append(f"-DCMAKE_CXX_FLAGS=-isystem{cxx_include}")
    configure = subprocess.run(args, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=180)
    if configure.returncode:
        raise RuntimeError(f"RAM probe CMake configure failed:\n{configure.stdout[-4000:]}")
    compile_result = subprocess.run([str(ninja), "-C", str(build)], cwd=ROOT, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    log = build / "build.log"
    log.write_text(compile_result.stdout, encoding="utf-8")
    image = build / "swid_ram_probe.bin"
    if compile_result.returncode or not image.exists():
        raise RuntimeError(f"RAM probe {target} build failed; see {log}")
    info = run_tool("-m", "esptool", "--chip", target, "image_info", str(image), timeout=45)
    if "Entry point:" not in info or "segments" not in info:
        raise RuntimeError("RAM probe image failed esptool segment validation")
    return {"target": target, "image": image, "image_bytes": image.stat().st_size,
            "elf": build / "swid_ram_probe.elf", "map": build / "swid_ram_probe.map",
            "image_info": info, "build_log": log,
            "sdkconfig_ram": "CONFIG_APP_BUILD_TYPE_RAM=y" in sdkconfig.read_text(encoding="utf-8"),
            "sdkconfig": sdkconfig}


def read_flash_hash(port: str, target: str, capacity: int) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="flash_read_", suffix=".bin", dir=OUT, delete=False) as handle:
        temp_path = pathlib.Path(handle.name)
    started = time.perf_counter()
    try:
        # Full-device snapshots are read-only, but 460800 baud can take longer
        # than four minutes for 16 MiB. Use the USB Serial/JTAG capable rate and
        # allow ample time for the complete transfer.
        run_tool("-m", "esptool", "--chip", target, "--port", port, "--baud", "2000000",
                 "--after", "no_reset", "read_flash", "0", hex(capacity), str(temp_path), timeout=420)
        if temp_path.stat().st_size != capacity:
            raise RuntimeError("full-flash read returned an unexpected byte count")
        digest = hashlib.sha256(temp_path.read_bytes()).hexdigest().upper()
        return {"capacity_bytes": capacity, "sha256": digest,
                "elapsed_seconds": time.perf_counter() - started, "read_only": True}
    finally:
        temp_path.unlink(missing_ok=True)


def capture_ram_probe(port: str, expected_mac: str, target: str, image: pathlib.Path,
                      timeout: float = 120.0) -> dict:
    try:
        import serial
    except ImportError as exc:
        raise RuntimeError("pyserial is required for RAM probe capture") from exc
    # A USB Serial/JTAG interface may disappear between discovery and this
    # call. Resolve by MAC immediately before opening the ROM loader.
    rom_identity = identify_expected_device(expected_mac, port, target)
    port = rom_identity["port"]
    if rom_identity["mac"] != expected_mac.upper():
        raise RuntimeError(f"RAM loader identity mismatch: expected {expected_mac}, got {rom_identity['mac']}")
    load_started = time.perf_counter()
    # The esptool RAM stub itself occupies the same internal DRAM window as
    # this IDF RAM image. Use the ROM loader to avoid address overlap.
    try:
        load_output = run_tool("-m", "esptool", "--no-stub", "--chip", target, "--port", port, "--baud", "460800",
                               "--after", "no_reset", "load_ram", str(image), timeout=90)
    except RuntimeError as exc:
        # Some USB Serial/JTAG drivers drop/recreate the COM handle as the RAM
        # image takes over USB. Treat this as successful transfer only when
        # esptool confirms every segment was sent and reports its entry point.
        detail = str(exc)
        if "All segments done, executing at" not in detail or "Cannot configure port" not in detail:
            raise
        load_output = detail
    port = resolve_enumerated_port(expected_mac, port)
    load_seconds = time.perf_counter() - load_started
    records = []
    console_lines = []
    started = time.perf_counter()
    deadline = started + timeout
    last_error = None
    while time.perf_counter() < deadline:
        try:
            # Opening with a port already assigned briefly asserts DTR on some
            # Windows drivers, resetting USB-Serial/JTAG and discarding the
            # volatile RAM image. Set modem lines before opening the handle.
            port = resolve_enumerated_port(expected_mac, port, attempts=1, delay=0)
            link = serial.Serial(port=None, baudrate=115200, timeout=0.2, write_timeout=2)
            link.port = port
            link.dtr = False
            link.rts = False
            link.open()
            try:
                while time.perf_counter() < deadline:
                    raw = link.readline().decode("utf-8", "replace").strip()
                    if not raw:
                        continue
                    console_lines.append(raw[:2048])
                    if not raw.startswith("{"):
                        continue
                    try:
                        item = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    records.append(item)
                    if item.get("type") == "complete":
                        return {"records": records, "load_seconds": load_seconds,
                                "capture_seconds": time.perf_counter() - started,
                                "load_output_sha256": hashlib.sha256(load_output.encode()).hexdigest().upper(),
                                "console_lines": console_lines,
                                "mac": expected_mac.upper(), "flash_write_attempted": False,
                                "efuse_write_attempted": False,
                                "software_reset_requested": any(x.get("type") == "software_reset_request" and
                                    x.get("method") == "esp_restart" for x in records)}
            finally:
                link.close()
        except (OSError, serial.SerialException) as exc:
            last_error = str(exc)
            time.sleep(0.2)
    raise TimeoutError(f"RAM probe produced no complete record on {port}; records={records}; "
                       f"console_tail={console_lines[-30:]}; {last_error or ''}")


def validate_ram_fingerprints(records: list[dict]) -> dict:
    by_type = {item.get("type"): item for item in records}
    chip, identity, memory, radio = (by_type.get(k) for k in ("chip", "identity", "memory", "radio"))
    peripherals = [item for item in records if item.get("type") == "peripheral"]
    fp_records = {item.get("kind"): item for item in records if item.get("type") == "fingerprint"}
    if not all((chip, identity, memory, radio)) or len(fp_records) != 3:
        raise RuntimeError("RAM probe output is incomplete; fingerprints not validated")
    manifest = {"chip": chip,
                "identity": {"mac": identity["mac"], "mac_valid": bool(identity["mac_valid"]),
                             "optional_uid": identity["optional_uid"],
                             "optional_uid_valid": bool(identity["optional_uid_valid"])},
                "memory": {"flash_jedec": memory["jedec"], "flash_capacity_bytes": memory["flash_capacity"],
                           "flash_unique_id": memory["flash_uid"],
                           "flash_unique_id_valid": bool(memory["flash_uid_valid"]),
                           "psram_capacity_bytes": memory["psram_capacity"],
                           "psram_present": bool(memory["psram_present"]),
                           "psram_interface": memory["psram_interface"], "psram_location": memory["psram_location"]},
                "radio": {"wifi_supported": radio["wifi"], "wifi_generation": radio["wifi_generation"],
                          "bluetooth_supported": radio["bluetooth"], "ble_supported": radio["ble"],
                  "bt_classic_supported": radio["bt_classic"],
                  "sta_mac": radio.get("sta_mac"), "ap_mac": radio.get("ap_mac"),
                  "bt_mac": radio.get("bt_mac"), "derived_mac_count": radio.get("derived_mac_count")},
                "peripherals": [{"type": p["peripheral_type"], "supported": p["supported"],
                                 "controllers": p["controllers"], "channels": p["channels"],
                                 "feature_flags": p["feature_flags"], "status": p["status"], "evidence": p["evidence"]}
                                for p in peripherals]}
    verified = {}
    for kind in ("silicon", "assembly", "profile"):
        data, digest = fingerprint(manifest, kind)
        received = fp_records[kind]
        verified[kind] = {"tlv_matches_device": data.hex().upper() == received["tlv_hex"],
                          "sha256_matches_device": digest == received["sha256"],
                          "tlv_sha256": digest, "tlv_bytes": len(data),
                          "tlv_hex": received["tlv_hex"], "sha256": received["sha256"]}
        if not verified[kind]["tlv_matches_device"] or not verified[kind]["sha256_matches_device"]:
            raise RuntimeError(f"host/C SWID v2 serialization mismatch for {kind}")
    summaries = [item for item in records if item.get("type") == "repeat_summary"]
    repeat_errors = [item for item in records if item.get("type") == "repeat_error"]
    expected_digests = {kind: item["sha256"] for kind, item in verified.items()}
    summary = summaries[-1] if len(summaries) == 1 else None
    repeat_consistent = bool(summary) and not repeat_errors and all((
        summary.get(f"{kind}_mismatches") == 0 and
        summary.get(f"first_{kind}") == expected_digests[kind] and
        summary.get(f"last_{kind}") == expected_digests[kind])
        for kind in ("silicon", "assembly", "profile"))
    return {"manifest": manifest, "fingerprints": verified, "peripheral_count": len(peripherals),
            "complete": len(peripherals) == by_type.get("peripheral_count", {}).get("count"),
            "repeat_sample_count": summary.get("count", 0) if summary else 0,
            "repeat_summary": summary, "repeat_errors": repeat_errors,
            "repeat_consistent": repeat_consistent,
            "repeat_samples": [summary] if summary else []}


def parse_tlv(data: bytes) -> list[tuple[int, bytes]]:
    fields = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 3:
            raise ValueError("truncated SWID TLV header")
        field = data[offset]
        length = int.from_bytes(data[offset + 1:offset + 3], "little")
        offset += 3
        if length > len(data) - offset:
            raise ValueError("truncated SWID TLV value")
        fields.append((field, data[offset:offset + length]))
        offset += length
    return fields


def capture_existing_flash_reference(mac: str, target: str, port: str,
                                     ram_validation: dict | None = None) -> dict:
    """Read the already-installed SWID v2 app over FP1; never programs flash."""
    if identify(port)["mac"] != mac.upper():
        raise RuntimeError("flash-reference port failed ROM MAC verification")
    run_tool("-m", "esptool", "--chip", target, "--port", port,
             "--baud", "460800", "--after", "hard_reset", "chip_id", timeout=45)
    from host.fp1 import FP1Session
    with FP1Session(mac, port) as session:
        profile = session.request("swid_profile")
        if not profile.get("valid") or profile.get("schema") != 2:
            raise RuntimeError("installed flash firmware did not provide a valid SWID v2 profile")
        compared = {}
        for kind in ("silicon", "assembly", "profile"):
            device_tlv = bytes.fromhex(session.request("swid_tlv", kind)["tlv_hex"])
            device_digest = hashlib.sha256(device_tlv).hexdigest().upper()
            flash_tlv_fields = parse_tlv(device_tlv)
            host_tlv = bytes.fromhex(ram_validation["fingerprints"][kind]["tlv_hex"]) if ram_validation else None
            ram_tlv_fields = parse_tlv(host_tlv) if host_tlv is not None else []
            field_differences = []
            if host_tlv is not None:
                field_names = {44: "bluetooth_classic_supported"}
                max_count = max(len(flash_tlv_fields), len(ram_tlv_fields))
                for index in range(max_count):
                    left = flash_tlv_fields[index] if index < len(flash_tlv_fields) else None
                    right = ram_tlv_fields[index] if index < len(ram_tlv_fields) else None
                    if left != right:
                        field_differences.append({"index": index, "flash_field": left[0] if left else None,
                                                  "ram_field": right[0] if right else None,
                                                  "flash_value_hex": left[1].hex().upper() if left else None,
                                                  "ram_value_hex": right[1].hex().upper() if right else None,
                                                  "field_name": field_names.get(left[0] if left else (right[0] if right else -1))})
            compared[kind] = {"device_tlv_sha256": hashlib.sha256(device_tlv).hexdigest().upper(),
                              "device_digest": profile[f"{kind if kind != 'profile' else 'profile'}_fingerprint"],
                              "digest_matches_tlv": device_digest == profile[f"{kind if kind != 'profile' else 'profile'}_fingerprint"],
                              "tlv_matches_ram_probe": device_tlv == host_tlv if host_tlv is not None else None,
                              "tlv_differences_vs_ram": field_differences if host_tlv is not None else None,
                              "tlv_hex": device_tlv.hex().upper()}
    return {"backend": "FLASH_FIRMWARE", "profile": profile,
            "fingerprints": compared,
            "flash_write_attempted": False, "evidence": "PHYSICAL_FP1_READ"}


def verify_existing_app_after_probe(mac: str, target: str, port: str) -> dict:
    run_tool("-m", "esptool", "--chip", target, "--port", port, "--baud", "460800",
             "--after", "hard_reset", "chip_id", timeout=45)
    from host.fp1 import FP1Session
    with FP1Session(mac, port) as session:
        pong = session.request("ping")
        profile = session.request("swid_profile")
    if profile.get("mac", "").upper() != mac.upper() or not profile.get("valid"):
        raise RuntimeError("post-probe flash application identity/profile verification failed")
    return {"reset": "READ_ONLY_HARD_RESET", "fp1_ping": pong,
            "profile_valid": profile["valid"], "profile_schema": profile.get("schema"),
            "mac": profile["mac"], "fingerprints": {k: profile[k] for k in
                ("silicon_fingerprint", "assembly_fingerprint", "profile_fingerprint")},
            "flash_write_attempted": False}


def save_rom_result(port: str, expected_mac: str | None) -> dict:
    result = read_only_rom_inventory(port, expected_mac)
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = OUT / f"rom_inventory_{result['identity']['mac'].replace(':', '')}_{stamp}.json"
    dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return {"path": str(dest), "result": result}


def write_backend_summary(result: dict) -> pathlib.Path:
    """Refresh the aggregate while keeping the original comparison key for old consumers."""
    dest = OUT / "backend_comparison.json"
    previous = None
    if dest.exists():
        try:
            old = json.loads(dest.read_text(encoding="utf-8"))
            previous = old.get("latest_result")
            if previous == result.get("result_path"):
                previous = old.get("previous_result")
        except (OSError, json.JSONDecodeError):
            previous = None
    if not previous:
        prior_runs = sorted((p for p in OUT.glob("ram_probe_*.json")
                             if str(p) != str(result.get("result_path"))),
                            key=lambda p: p.stat().st_mtime)
        if prior_runs:
            previous = str(prior_runs[-1])
    summary = {"latest_result": result.get("result_path"),
               "device_mac": result.get("identity", {}).get("mac"),
               "target": result.get("identity", {}).get("model"),
               "flash_unchanged": result.get("flash_unchanged"),
               "comparison": result.get("backend_comparison", {}),
               "backends": result.get("backend_comparison", {})}
    if previous:
        summary["previous_result"] = previous
    dest.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return dest


def run_ram_campaign(port: str, expected_mac: str | None,
                     rom_inventory: dict | None = None, repeat_count: int = 50,
                     verify_flash: bool = False, check_fp1: bool = False,
                     probe_artifact: dict | None = None) -> dict:
    ident = identify_expected_device(expected_mac, port) if expected_mac else identify(port)
    port = ident["port"]
    if expected_mac and ident["mac"] != expected_mac.upper():
        raise RuntimeError(f"MAC mismatch: expected {expected_mac}, got {ident['mac']}")
    target = ident["model"].lower().replace("-", "")
    if target not in RAM_PROBE_BUILD_VERIFIED_TARGETS:
        raise RuntimeError(f"no RAM build verified for {ident['model']}")
    inventory = rom_inventory or read_only_rom_inventory(port, ident["mac"])
    if inventory.get("identity", {}).get("mac", "").upper() != ident["mac"]:
        raise RuntimeError("cached ROM inventory identity does not match the live ROM MAC")
    if inventory.get("identity", {}).get("model", "").upper() != ident["model"].upper():
        raise RuntimeError("cached ROM inventory target does not match the live ROM model")
    OUT.mkdir(parents=True, exist_ok=True)
    capacity = (inventory.get("flash") or {}).get("capacity_bytes_reported")
    baseline = None
    flash_integrity_error = None
    if verify_flash and capacity:
        try:
            baseline = read_flash_hash(port, target, capacity)
        except (RuntimeError, OSError, TimeoutError) as exc:
            flash_integrity_error = f"PRE_CAPTURE_READ_FAILED: {exc}"
    if verify_flash and not capacity:
        flash_integrity_error = "PRE_CAPTURE_READ_UNAVAILABLE: ROM did not report flash capacity"
    artifact = probe_artifact or build_ram_probe(target, repeat_count, restart_after_capture=True)
    capture = capture_ram_probe(port, ident["mac"], target, artifact["image"])
    validated = validate_ram_fingerprints(capture["records"])
    flash_reference = None
    fp1_error = None
    if check_fp1:
        try:
            flash_reference = capture_existing_flash_reference(ident["mac"], target, port, validated)
        except (RuntimeError, OSError, TimeoutError) as exc:
            fp1_error = str(exc)
    after = None
    if baseline:
        try:
            after = read_flash_hash(port, target, capacity)
        except (RuntimeError, OSError, TimeoutError) as exc:
            flash_integrity_error = f"POST_CAPTURE_READ_FAILED: {exc}"
    flash_unchanged = (baseline["sha256"] == after["sha256"]) if baseline and after else None
    final_app_check = None
    if check_fp1 and flash_reference:
        try:
            final_app_check = verify_existing_app_after_probe(ident["mac"], target, port)
        except (RuntimeError, OSError, TimeoutError) as exc:
            fp1_error = str(exc)
    result = {"schema": 1, "identity": ident, "rom_inventory": inventory,
              "probe": {"target": target, "image_bytes": artifact["image_bytes"],
                        "image_sha256": hashlib.sha256(artifact["image"].read_bytes()).hexdigest().upper(),
                        "image_path": str(artifact["image"]),
                        "repeat_count_per_capture": repeat_count,
                        "restart_after_capture": True,
                        "ram_config": artifact["sdkconfig_ram"], "load_seconds": capture["load_seconds"],
                        "capture_seconds": capture["capture_seconds"], "ram_write_only": True},
              "baseline_flash": baseline, "post_probe_flash": after,
              "flash_unchanged": flash_unchanged,
              "flash_integrity_error": flash_integrity_error,
              "capture": capture["records"], "host_validation": validated,
              "flash_firmware_reference": flash_reference,
              "original_flash_app_check": final_app_check,
              "existing_fp1_reference": "AVAILABLE" if flash_reference else "NOT_AVAILABLE_OR_NOT_REQUESTED",
              "existing_fp1_error": fp1_error,
              "original_firmware_return": "RESET_REQUESTED_UNVERIFIED" if capture.get("software_reset_requested") else "NOT_REQUESTED",
              "write_operations_attempted": [], "flash_write_attempted": False,
              "efuse_write_attempted": False, "otp_write_attempted": False,
              "nvs_write_attempted": False}
    dest = OUT / f"ram_probe_{ident['mac'].replace(':', '')}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    result["result_path"] = str(dest)
    backends = {
        "ROM_ONLY": {"supported_targets": {"ESP32-S3": "HARDWARE_VERIFIED", "ESP32-C3": "NOT_CONNECTED"},
                     "fields_observed": 10,
                     "field_sources": ["ROM chip identity/features", "flash JEDEC", "detected flash capacity", "ROM PSRAM feature"],
                     "fingerprint_availability": "UNAVAILABLE (incomplete normalized SWID manifest)", "scheme_v2_match": False,
                     "ram_bytes": None, "measurement_seconds": inventory["elapsed_seconds"],
                     "safety_assumptions": ["ROM download interface is enabled", "only chip_id/flash_id/read operations used"],
                     "flash_unchanged": result["flash_unchanged"], "testing": "PHYSICAL_READ_ONLY"},
        "EFUSE_READONLY": {"supported_targets": ident["model"],
                           "fields_observed": len(inventory["efuse_summary"]["safe_fields"]),
                           "field_names": sorted(inventory["efuse_summary"]["safe_fields"]),
                           "fingerprint_availability": "UNAVAILABLE_WITHOUT_COMPLETE_MANIFEST", "scheme_v2_match": False,
                           "ram_bytes": None, "measurement_seconds": inventory["elapsed_seconds"],
                           "safety_assumptions": ["strict whitelist", "key block payloads excluded", "summary command is read-only"],
                           "flash_unchanged": result["flash_unchanged"], "testing": "PHYSICAL_WHITELISTED_READ_ONLY"},
        "RAM_PROBE": {"supported_targets_build_verified": sorted(x.upper() for x in RAM_PROBE_BUILD_VERIFIED_TARGETS),
                      "target_hardware_tested": ident["model"], "fields_observed": len(capture["records"]),
                      "peripheral_capabilities": validated["peripheral_count"],
                      "fingerprints": {k: v["sha256"] for k, v in validated["fingerprints"].items()},
                      "scheme_v2_match": all(v["tlv_matches_device"] and v["sha256_matches_device"] for v in validated["fingerprints"].values()),
                      "ram_image_bytes": artifact["image_bytes"],
                      "free_internal_heap_bytes": next(x["free_internal_heap"] for x in capture["records"] if x.get("type") == "swid_ram_probe"),
                      "stack_high_water_words": next(x["stack_high_water_words"] for x in capture["records"] if x.get("type") == "swid_ram_probe"),
                      "load_seconds": capture["load_seconds"], "capture_seconds": capture["capture_seconds"],
                      "safety_assumptions": ["esptool ROM loader; no-stub RAM transfer", "probe uses RAM and read-only identity APIs", "PSRAM interface initialized with memory test disabled", "no flash/eFuse/OTP/NVS writes"],
                      "flash_unchanged": result["flash_unchanged"], "testing": "PHYSICAL_RAM_ONLY"},
        "FLASH_FIRMWARE": {"supported_targets": ident["model"],
                           "fields_observed": len(flash_reference["fingerprints"]) if flash_reference else 0,
                           "fingerprints": {k: v["device_digest"] for k, v in flash_reference["fingerprints"].items()} if flash_reference else None,
                           "device_digest_matches_received_tlv": {k: v["digest_matches_tlv"] for k, v in flash_reference["fingerprints"].items()} if flash_reference else None,
                           "same_tlv_as_ram_probe": {k: v["tlv_matches_ram_probe"] for k, v in flash_reference["fingerprints"].items()} if flash_reference else None,
                           "ram_bytes": "RUNNING_APP_NOT_PROFILED", "measurement_seconds": None,
                           "safety_assumptions": ["pre-existing firmware only", "FP1 reads plus reset", "no flashing or device provisioning"],
                           "post_probe_application_check": final_app_check,
                           "flash_unchanged": result["flash_unchanged"],
                           "testing": "EXISTING_APP_READ_ONLY_FP1" if flash_reference else "NOT_REQUESTED_OR_UNAVAILABLE"},
    }
    result["backend_comparison"] = backends
    dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_backend_summary(result)
    return result


def run_ram_reset_campaign(port: str, mac: str, target: str, image: pathlib.Path,
                           baseline_validation: dict, repeat_count: int = 1000,
                           reset_count: int = 20, progress=None,
                           flash_reference: dict | None = None) -> dict:
    """Collect repeated SWID profiles in RAM after each confirmed software reset."""
    if repeat_count < 1 or repeat_count > 1000 or reset_count < 0:
        raise ValueError("repeat_count must be 1..1000 and reset_count must be nonnegative")
    if reset_count < 1 or repeat_count % reset_count:
        raise ValueError("RAM Probe repeated sampling requires repeat_count divisible by reset_count")
    samples_per_reset = repeat_count // reset_count
    if not 1 <= samples_per_reset <= 100:
        raise ValueError("per-reset RAM Probe sampling count must be in 1..100")
    expected = {kind: item["sha256"] for kind, item in baseline_validation["fingerprints"].items()}
    reference = (flash_reference or {}).get("fingerprints", {})
    fp1_baseline = {kind: reference.get(kind, {}).get("device_digest")
                    for kind in ("silicon", "assembly", "profile")}
    if flash_reference and (fp1_baseline["silicon"] != expected["silicon"] or
                            fp1_baseline["assembly"] != expected["assembly"]):
        raise RuntimeError("saved FP1 reference does not match RAM silicon/assembly fingerprints")
    profile_differences = reference.get("profile", {}).get("tlv_differences_vs_ram", [])
    legacy_radio_delta = (len(profile_differences) == 1 and
                          profile_differences[0].get("flash_field") == 44 and
                          profile_differences[0].get("ram_field") == 44 and
                          profile_differences[0].get("flash_value_hex") == "01" and
                          profile_differences[0].get("ram_value_hex") == "00")
    if flash_reference and fp1_baseline["profile"] != expected["profile"] and not legacy_radio_delta:
        raise RuntimeError("saved FP1/RAM profile differs outside the known legacy Bluetooth Classic field")

    if baseline_validation.get("repeat_sample_count") != samples_per_reset or not baseline_validation.get("repeat_consistent"):
        raise RuntimeError("RAM Probe build/capture repeat count does not match reset campaign")
    current = identify_expected_device(mac, port, target)
    port = current["port"]
    run_tool("-m", "esptool", "--chip", target, "--port", port, "--baud", "460800",
             "--after", "hard_reset", "chip_id", timeout=45)
    resets = []
    all_samples = []
    for index in range(reset_count):
        current = identify_expected_device(mac, port, target)
        port = current["port"]
        capture = capture_ram_probe(port, mac, target, image)
        if not any(item.get("type") == "software_reset_request" and
                   item.get("method") == "esp_restart" for item in capture["records"]):
            raise RuntimeError(f"RAM Probe did not emit software-reset request after cycle {index + 1}")
        validated = validate_ram_fingerprints(capture["records"])
        ram_values = {kind: item["sha256"] for kind, item in validated["fingerprints"].items()}
        summaries = validated.get("repeat_samples", [])
        if (ram_values != expected or not validated.get("complete") or
                not validated.get("repeat_consistent") or len(summaries) != 1 or
                summaries[0].get("count") != samples_per_reset):
            raise RuntimeError(f"RAM Probe mismatch after software reset cycle {index + 1}")
        all_samples.extend(summaries)

        # RAM probe's explicit esp_restart marker is the reset evidence. The
        # application that resumes is arbitrary; FP1 is an optional reference.
        fp1_values = None
        app_recovered = None
        if flash_reference:
            from host.fp1 import FP1Session
            after = None
            last_error = None
            for _ in range(5):
                try:
                    with FP1Session(mac, port) as session:
                        after = session.request("swid_profile", timeout=15)
                    if after.get("valid"):
                        break
                except (OSError, TimeoutError) as exc:
                    last_error = str(exc)
                    time.sleep(1)
            if not after or not after.get("valid"):
                raise RuntimeError(f"FP1 reference app did not recover after RAM reset {index + 1}: {last_error}")
            fp1_values = {"silicon": after.get("silicon_fingerprint"),
                          "assembly": after.get("assembly_fingerprint"),
                          "profile": after.get("profile_fingerprint")}
            if fp1_values != fp1_baseline:
                raise RuntimeError(f"installed-app fingerprints changed after RAM reset {index + 1}")
            app_recovered = True

        row = {"index": index + 1, "software_reset_invocation_confirmed": True,
               "reset_reason": "NOT_EXPOSED_BY_INSTALLED_APP",
               "reset_evidence": "RAM_PROBE_ESP_RESTART_MARKER",
               "fp1_fingerprints": fp1_values,
               "ram_probe_reloaded": True, "ram_fingerprints": ram_values,
               "repeat_summary": summaries[0],
               "ram_matches_baseline": True, "application_recovered": app_recovered,
               "ram_load_seconds": capture["load_seconds"],
               "ram_capture_seconds": capture["capture_seconds"]}
        resets.append(row)
        if progress:
            progress({"completed": index + 1, "requested": reset_count,
                      "completed_repeats": sum(x.get("count", 0) for x in all_samples),
                      "last": row, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

    complete = sum(item.get("count", 0) for item in all_samples) == repeat_count
    return {"status": "PASS" if len(resets) == reset_count and complete else "INCOMPLETE",
            "requested_repeats": repeat_count, "samples_per_reset": samples_per_reset,
            "repeated_measurements": all_samples,
            "benchmark_complete": complete, "software_resets_requested": reset_count,
            "software_resets_verified": sum(x["software_reset_invocation_confirmed"] for x in resets),
            "ram_probe_reloads_verified": sum(x["ram_probe_reloaded"] for x in resets),
            "reset_observations": resets, "expected_fingerprints": expected,
            "installed_app_fingerprints": fp1_baseline if flash_reference else None,
            "known_legacy_profile_divergence": {"allowed": legacy_radio_delta,
                "field_id": 44 if legacy_radio_delta else None,
                "installed_app_value": "01" if legacy_radio_delta else None,
                "ram_value": "00" if legacy_radio_delta else None},
            "note": "Each RAM Probe performs repeat_count_per_capture complete SWID collections, emits a software-reset request and calls esp_restart(). The next iteration confirms ROM loader availability and reloads the RAM image. FP1 recovery is optional and only runs when an FP1 reference is supplied. No flash writes are performed."}


def run_existing_flash_backend(port: str, expected_mac: str | None) -> dict:
    ident = identify(port)
    if expected_mac and ident["mac"] != expected_mac.upper():
        raise RuntimeError(f"MAC mismatch: expected {expected_mac}, got {ident['mac']}")
    target = ident["model"].lower().replace("-", "")
    reference = capture_existing_flash_reference(ident["mac"], target, port)
    result = {"schema": 1, "identity": ident, "backend": reference,
              "flash_write_attempted": False, "efuse_write_attempted": False}
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / f"flash_backend_{ident['mac'].replace(':', '')}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    result["result_path"] = str(dest)
    dest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", help="Explicit USB serial port; no write commands are available")
    parser.add_argument("--mac", help="Expected ROM MAC; abort on mismatch")
    parser.add_argument("--list", action="store_true", help="List USB serial devices without connecting")
    parser.add_argument("--mode", choices=("auto", "rom-only", "ram-only", "flash"), default="auto",
                        help="auto prefers ROM+RAM; rom-only reads ROM/eFuse; ram-only adds RAM probe; flash reads installed app only")
    parser.add_argument("--verify-flash", action="store_true",
                        help="read complete flash before/after RAM capture and compare SHA-256 (read-only, slow)")
    parser.add_argument("--check-fp1", action="store_true",
                        help="optionally compare against an already-installed SWID FP1 app; RAM Probe does not require it")
    args = parser.parse_args()
    if args.list:
        print(json.dumps(candidates(), indent=2))
        return 0
    port = args.port
    if not port:
        devices = discover_rom_devices()
        if args.mac:
            devices = [item for item in devices if item["mac"].upper() == args.mac.upper()]
        if len(devices) != 1:
            raise RuntimeError("automatic selection requires exactly one matching ESP32; found: " +
                               json.dumps(devices))
        port = devices[0]["port"]
    mode = args.mode
    if mode == "auto":
        auto_ident = identify_expected_device(args.mac, port) if args.mac else identify(port)
        port = auto_ident["port"]
        if args.mac and auto_ident["mac"] != args.mac.upper():
            raise RuntimeError(f"MAC mismatch: expected {args.mac}, got {auto_ident['mac']}")
        mode = select_backend(mode, auto_ident["model"])
    if mode == "ram-only":
        result = run_ram_campaign(port, args.mac, verify_flash=args.verify_flash,
                                  check_fp1=args.check_fp1)
    elif mode == "flash":
        result = run_existing_flash_backend(port, args.mac)
    else:
        result = save_rom_result(port, args.mac)
    if mode == "ram-only":
        summary = {"result_path": result.get("result_path"), "mac": result["identity"]["mac"],
                   "target": result["probe"]["target"], "probe_image_bytes": result["probe"]["image_bytes"],
                   "flash_unchanged": result["flash_unchanged"],
                   "peripheral_count": result["host_validation"]["peripheral_count"],
                   "ram_fingerprints": {k: v["sha256"] for k, v in result["host_validation"]["fingerprints"].items()},
                   "flash_reference_matches": ({k: v["tlv_matches_ram_probe"] for k, v in result["flash_firmware_reference"]["fingerprints"].items()}
                                               if result["flash_firmware_reference"] else None),
                   "original_firmware_return": result["original_firmware_return"]}
        print(json.dumps(summary, indent=2))
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
