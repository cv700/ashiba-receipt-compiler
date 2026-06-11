#!/usr/bin/env python3
"""Execute shell commands on a RunPod pod via the Jupyter kernel websocket.

RunPod's basic SSH gateway (ssh.runpod.io) does not support non-interactive
exec, so this drives the pod's Jupyter server instead, with a hand-rolled
RFC 6455 client (stdlib only).

Usage:
    runpod_jexec.py 'nvidia-smi -L'
    runpod_jexec.py --timeout 600 'apt-get update'

Environment:
    ARC_JUPYTER_BASE   e.g. https://<pod>-8888.proxy.runpod.net
    ARC_JUPYTER_TOKEN  Jupyter token
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE = os.environ.get("ARC_JUPYTER_BASE", "https://paq3wmi0tn3dep-8888.proxy.runpod.net")
TOKEN = os.environ.get("ARC_JUPYTER_TOKEN", "587tqwa28jzaj3oph3e9")
STATE = Path.home() / ".arc_runpod_kernel"


def _api(method: str, path: str, body: dict | None = None) -> dict:
    sep = "&" if "?" in path else "?"
    req = urllib.request.Request(
        f"{BASE}{path}{sep}token={TOKEN}",
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.6.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def get_kernel() -> str:
    if STATE.is_file():
        kid = STATE.read_text().strip()
        try:
            alive = {k["id"] for k in _api("GET", "/api/kernels")}
            if kid in alive:
                return kid
        except Exception:
            pass
    kid = _api("POST", "/api/kernels", {"name": "python3"})["id"]
    STATE.write_text(kid)
    return kid


class WS:
    def __init__(self, host: str, path: str, timeout: float):
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(socket.create_connection((host, 443), timeout=30), server_hostname=host)
        self.sock.settimeout(timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "User-Agent: curl/8.6.0\r\n\r\n"
        )
        self.sock.sendall(handshake.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("handshake: connection closed")
            resp += chunk
        status = resp.split(b"\r\n", 1)[0].decode()
        if "101" not in status:
            raise ConnectionError(f"handshake failed: {status}")
        self.buf = resp.split(b"\r\n\r\n", 1)[1]

    def _recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed mid-frame")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_text(self, payload: str) -> None:
        data = payload.encode()
        mask = secrets.token_bytes(4)
        header = bytes([0x81])
        n = len(data)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(header + mask + masked)

    def recv_message(self) -> str | None:
        """Return the next complete text message, transparently handling ping/close."""
        fragments = []
        while True:
            b1, b2 = self._recv_exact(2)
            fin, opcode = b1 & 0x80, b1 & 0x0F
            masked, n = b2 & 0x80, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._recv_exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._recv_exact(8))[0]
            mask = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 9:  # ping -> pong
                pong_mask = secrets.token_bytes(4)
                self.sock.sendall(bytes([0x8A, 0x80 | len(payload)]) + pong_mask
                                  + bytes(b ^ pong_mask[i % 4] for i, b in enumerate(payload)))
                continue
            if opcode == 8:
                return None
            if opcode in (1, 2, 0):
                fragments.append(payload)
                if fin:
                    return b"".join(fragments).decode("utf-8", "replace")


def run_code(code: str, timeout: float) -> int:
    kid = get_kernel()
    host = BASE.split("://", 1)[1]
    session = uuid.uuid4().hex
    msg_id = uuid.uuid4().hex
    ws = WS(host, f"/api/kernels/{kid}/channels?token={TOKEN}", timeout)
    ws.send_text(json.dumps({
        "header": {
            "msg_id": msg_id, "username": "arc", "session": session,
            "msg_type": "execute_request", "version": "5.3",
            "date": datetime.now(timezone.utc).isoformat(),
        },
        "parent_header": {}, "metadata": {}, "channel": "shell",
        "content": {
            "code": code, "silent": False, "store_history": False,
            "user_expressions": {}, "allow_stdin": False, "stop_on_error": False,
        },
    }))
    got_reply = idle = False
    rc = 0
    while not (got_reply and idle):
        raw = ws.recv_message()
        if raw is None:
            print("[jexec] websocket closed early", file=sys.stderr)
            return 70
        msg = json.loads(raw)
        if msg.get("parent_header", {}).get("msg_id") != msg_id:
            continue
        mtype, content = msg.get("msg_type"), msg.get("content", {})
        if mtype == "stream":
            out = sys.stdout if content.get("name") == "stdout" else sys.stderr
            out.write(content.get("text", ""))
            out.flush()
        elif mtype == "error":
            print("\n".join(content.get("traceback", [])), file=sys.stderr)
            rc = 1
        elif mtype == "execute_reply":
            got_reply = True
            if content.get("status") == "error":
                rc = rc or 1
        elif mtype == "status" and content.get("execution_state") == "idle":
            idle = True
    return rc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--python", action="store_true", help="run raw python code instead of shell")
    args = parser.parse_args()
    if args.python:
        code = args.command
    else:
        code = (
            "import subprocess, sys\n"
            f"_r = subprocess.run(['bash', '-lc', {args.command!r}], capture_output=True, text=True)\n"
            "sys.stdout.write(_r.stdout)\n"
            "sys.stderr.write(_r.stderr)\n"
            "sys.stdout.write('\\n__JEXEC_RC=' + str(_r.returncode) + '\\n')\n"
        )
    return run_code(code, args.timeout)


if __name__ == "__main__":
    raise SystemExit(main())
