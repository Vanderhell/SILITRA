"""FP1 framing and session helpers used by SWID acquisition."""

import json
import time
import uuid
import zlib


def crc32_text(value: str) -> str:
    return f"{zlib.crc32(value.encode('ascii')) & 0xFFFFFFFF:08X}"


def make_frame(request_id: str, command: str, payload: str = "") -> bytes:
    body = f"FP1|{request_id}|{command}|{len(payload)}|{payload}"
    return f"{body}|{crc32_text(body)}\n".encode("ascii")


def parse_frame(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("FP1|"):
        return None
    parts = line.rsplit("|", 1)
    if len(parts) != 2:
        return None
    body, received = parts
    if crc32_text(body) != received.upper():
        return None
    fields = body.split("|", 4)
    if len(fields) != 5 or fields[0] != "FP1":
        return None
    try:
        declared_length = int(fields[3])
    except ValueError:
        return None
    if declared_length != len(fields[4]):
        return None
    return {"request_id": fields[1], "kind": fields[2], "payload": fields[4]}


class FP1Session:
    """Open one already ROM-identified serial port for FP1 requests."""

    def __init__(self, mac: str, port: str):
        import serial

        self.mac = mac.upper()
        self.port = port
        self.reset_pending = False
        try:
            from serial.tools import list_ports
            descriptor = next((item for item in list_ports.comports()
                               if item.device.upper() == port.upper()), None)
        except ImportError:
            descriptor = None
        self.transport = "usb_serial_jtag" if descriptor and descriptor.vid == 0x303A else "uart0"
        self.ser = serial.Serial(port, 115200, timeout=0.3, write_timeout=5)
        if self.transport == "uart0":
            time.sleep(1.0)
            self.ser.reset_input_buffer()
        else:
            self.ser.dtr = False
            self.ser.rts = False
            time.sleep(1.0)
            self.ser.reset_input_buffer()

    def close(self):
        self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def request(self, command: str, payload: str = "", timeout: float = 20) -> dict:
        if self.reset_pending:
            time.sleep(3.0)
            self.reset_pending = False
        request_id = "swid-" + uuid.uuid4().hex[:10]
        encoded = make_frame(request_id, command, payload)
        for _attempt in range(2):
            self.ser.write(encoded)
            self.ser.flush()
            deadline = time.monotonic() + timeout / 2
            while time.monotonic() < deadline:
                frame = parse_frame(self.ser.readline().decode("ascii", "replace"))
                if not frame or frame["request_id"] != request_id:
                    continue
                expected_kind = "pong" if command == "ping" else command
                if frame["kind"] not in {expected_kind, "immutable_identity"}:
                    continue
                value = json.loads(frame["payload"])
                returned_mac = value.get("mac")
                if returned_mac and returned_mac.upper() != self.mac:
                    raise RuntimeError(f"FP1 identity mismatch: expected {self.mac}, received {returned_mac}")
                if command == "software_reset" and value.get("accepted"):
                    self.reset_pending = True
                return value
        raise TimeoutError(f"FP1 session timeout on {self.mac} command={command}")

    def stream(self, command: str, payload: str = "", timeout: float = 30) -> list[tuple[str, dict]]:
        request_id = "swid-" + uuid.uuid4().hex[:10]
        self.ser.write(make_frame(request_id, command, payload))
        self.ser.flush()
        frames = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            frame = parse_frame(self.ser.readline().decode("ascii", "replace"))
            if not frame or frame["request_id"] != request_id:
                continue
            if frame["kind"] == "complete":
                return frames
            value = json.loads(frame["payload"])
            returned_mac = value.get("mac")
            if returned_mac and returned_mac.upper() != self.mac:
                raise RuntimeError(f"FP1 stream identity mismatch: expected {self.mac}, received {returned_mac}")
            frames.append((frame["kind"], value))
        raise TimeoutError(f"FP1 stream timeout on {self.mac} command={command}, frames={len(frames)}")
