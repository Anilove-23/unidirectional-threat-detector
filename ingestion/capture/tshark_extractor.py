"""
capture/tshark_extractor.py
============================
Runs tshark as a subprocess, filtered to TLS ClientHello packets only.
Extracts the precise cipher-suite list and extension list (in order)
needed to build JA3/JA4 fingerprints.

Why tshark and not Zeek for this?
  Zeek's JA3 plugin gives you the final hash, but not the raw ordered
  field list. Order of cipher suites is a fingerprint signal itself —
  malware TLS stacks often present ciphers in a non-standard order.
  tshark's dissector gives us the exact field values as they appear on wire.

In SIMULATION mode with loopback or no live TLS traffic, this component
simply produces no output (it only fires on TLS ClientHello packets).
"""
from __future__ import annotations

import subprocess
import threading
import structlog

from config.settings import settings
from processing.tls_parser import build_ja3_fingerprint
from processing.flow_object import TLSMeta
from monitoring.metrics import TSHARK_ALIVE

log = structlog.get_logger()

# tshark fields extracted per TLS ClientHello packet
_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tls.handshake.version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extension.type",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.extensions_ec_point_format",
    "tls.record.length",
    "quic.version",
]
_SEP = "|"


class TsharkExtractor:
    """
    Runs tshark as a subprocess and emits TLSMeta objects to the FlowAssembler.
    """

    def __init__(self, flow_assembler=None):
        self._assembler = flow_assembler
        self._proc      = None
        self._stop      = threading.Event()

    def start(self, iface: str = None) -> None:
        iface = iface or settings.capture_interface
        if settings.capture_mode == "loopback":
            iface = "lo"

        cmd = [
            "tshark",
            "-i", iface,
            "-l",          # line-buffered: emit output immediately per packet
            "-n",          # no name resolution (faster + no DNS queries from monitoring enclave)
            "-Y", "tls.handshake.type==1 or quic",   # filter: ClientHello + QUIC only
            "-T", "fields",
            "-E", f"separator={_SEP}",
            "-E", "occurrence=a",                    # all occurrences of repeated fields
        ]
        for field in _FIELDS:
            cmd += ["-e", field]

        log.info("tshark_starting", iface=iface)
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout  = subprocess.PIPE,
                stderr  = subprocess.DEVNULL,   # suppress tshark diagnostic noise
                bufsize = 1,
                text    = True,
            )
            TSHARK_ALIVE.set(1)
        except FileNotFoundError:
            log.warning("tshark_not_found", msg="tshark not found — TLS fingerprinting disabled. Install: sudo apt install tshark")
            TSHARK_ALIVE.set(0)
            return

        threading.Thread(
            target = self._read_output,
            daemon = True,
            name   = "tshark-reader",
        ).start()
        threading.Thread(
            target = self._health_monitor,
            daemon = True,
            name   = "tshark-health",
        ).start()

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
        TSHARK_ALIVE.set(0)
        log.info("tshark_stopped")

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ── Private ────────────────────────────────────────────────────────────────

    def _read_output(self) -> None:
        if not self._proc:
            return
        for raw_line in self._proc.stdout:
            if self._stop.is_set():
                break
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(_SEP)
            if len(parts) < len(_FIELDS):
                continue
            try:
                self._process_record(parts)
            except Exception as e:
                log.debug("tshark_parse_skip", error=str(e))

    def _process_record(self, parts: list[str]) -> None:
        record = dict(zip(_FIELDS, parts))

        src_ip   = record.get("ip.src", "").strip()
        dst_ip   = record.get("ip.dst", "").strip()
        src_port = int(record.get("tcp.srcport", "0").strip() or 0)
        dst_port = int(record.get("tcp.dstport", "0").strip() or 0)

        if not (src_ip and dst_ip):
            return

        # Parse comma-separated field lists from tshark output
        ciphers    = [c.strip() for c in record.get("tls.handshake.ciphersuite", "").split(",") if c.strip()]
        extensions = [e.strip() for e in record.get("tls.handshake.extension.type", "").split(",") if e.strip()]
        ec_curves  = [g.strip() for g in record.get("tls.handshake.extensions_supported_group", "").split(",") if g.strip()]
        ec_points  = [p.strip() for p in record.get("tls.handshake.extensions_ec_point_format", "").split(",") if p.strip()]
        tls_ver    = record.get("tls.handshake.version", "").strip()
        rec_len    = record.get("tls.record.length", "").strip()
        is_quic    = bool(record.get("quic.version", "").strip())

        ja3_raw, ja3_hash = build_ja3_fingerprint(tls_ver, ciphers, extensions, ec_curves, ec_points)

        tls_meta = TLSMeta(
            tls_version       = tls_ver or None,
            cipher_suites     = ciphers     or None,
            extensions        = extensions  or None,
            ec_curves         = ec_curves   or None,
            ja3_raw_string    = ja3_raw,
            ja3_fingerprint   = ja3_hash,
            record_length     = int(rec_len) if rec_len.isdigit() else None,
            is_quic           = is_quic,
        )

        if self._assembler:
            self._assembler.attach_tls_meta(src_ip, dst_ip, src_port, dst_port, tls_meta)
            log.debug("tls_meta_attached", src=src_ip, ja3=ja3_hash)

    def _health_monitor(self) -> None:
        import time
        while not self._stop.is_set():
            time.sleep(5)
            TSHARK_ALIVE.set(1 if self.is_alive() else 0)
