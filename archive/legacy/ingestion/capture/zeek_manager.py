"""
capture/zeek_manager.py
=======================
Manages the Zeek subprocess lifecycle.

Spawns: zeek -i <iface> -C local.zeek
Tails:  conn.log, ssl.log, dns.log in background threads

When a conn.log line is parsed, calls flow_assembler.attach_zeek_meta()
so that FlowObjects are enriched with Zeek's conn_state and UID.

In SIMULATION mode with a .pcap file, Zeek is run offline:
  zeek -r <pcap_file> local.zeek
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
import structlog

from config.settings import settings
from monitoring.metrics import ZEEK_ALIVE

log = structlog.get_logger()

# Zeek conn.log field indices (0-based, tab-separated)
_TS        = 0
_UID       = 1
_SRC_IP    = 2
_SRC_PORT  = 3
_DST_IP    = 4
_DST_PORT  = 5
_PROTO     = 6
_CONN_STATE = 11


class ZeekManager:
    """
    Manages Zeek as a subprocess and tails its log files.
    Provides on_conn_record and on_ssl_record callbacks for the FlowAssembler.
    """

    def __init__(self, flow_assembler=None):
        self._assembler   = flow_assembler
        self._proc        = None
        self._stop_event  = threading.Event()
        self._log_dir     = settings.zeek_log_dir

    def start(self, mode: str = "live", pcap_file: str = "") -> None:
        """
        mode: "live"      → zeek -i <interface> -C local.zeek
              "offline"   → zeek -r <pcap_file> local.zeek
              "disabled"  → Zeek skipped (simulation without Zeek)
        """
        os.makedirs(self._log_dir, exist_ok=True)
        script_path = os.path.join(settings.zeek_scripts_dir, "local.zeek")

        if mode == "disabled":
            log.info("zeek_disabled_in_simulation_mode")
            ZEEK_ALIVE.set(0)
            return

        if mode == "offline":
            if not pcap_file:
                log.warning("zeek_offline_no_pcap")
                return
            cmd = ["zeek", "-r", pcap_file, script_path]
        else:
            iface = settings.capture_interface
            cmd   = ["zeek", "-i", iface, "-C", script_path]

        log.info("zeek_starting", cmd=" ".join(cmd), log_dir=self._log_dir)

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                cwd    = self._log_dir,
            )
            ZEEK_ALIVE.set(1)
        except FileNotFoundError:
            log.warning("zeek_not_found", msg="Zeek binary not found — skipping. Install with: sudo apt install zeek")
            ZEEK_ALIVE.set(0)
            return

        # Tail log files in background threads
        for filename, parser in [
            ("conn.log", self._parse_conn_line),
            ("ssl.log",  self._parse_ssl_line),
            ("dns.log",  self._parse_dns_line),
        ]:
            threading.Thread(
                target = self._tail_log,
                args   = (filename, parser),
                daemon = True,
                name   = f"zeek-tail-{filename}",
            ).start()

        threading.Thread(target=self._stderr_drain, daemon=True, name="zeek-stderr").start()
        threading.Thread(target=self._health_monitor, daemon=True, name="zeek-health").start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        ZEEK_ALIVE.set(0)
        log.info("zeek_stopped")

    def is_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ── Log tailers ───────────────────────────────────────────────────────────

    def _tail_log(self, filename: str, parser) -> None:
        """Wait for file to appear, then tail new lines as they arrive."""
        path = os.path.join(self._log_dir, filename)
        while not os.path.exists(path) and not self._stop_event.is_set():
            time.sleep(0.5)
        if self._stop_event.is_set():
            return
        with open(path, "r") as f:
            # Skip existing header comment lines
            for line in f:
                if line.startswith("#"):
                    continue
            # Tail new lines
            while not self._stop_event.is_set():
                line = f.readline()
                if line:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            parser(line)
                        except Exception as e:
                            log.debug("zeek_parse_error", file=filename, error=str(e))
                else:
                    time.sleep(0.05)

    def _parse_conn_line(self, line: str) -> None:
        fields = line.split("\t")
        if len(fields) < 12:
            return
        try:
            uid        = fields[_UID]
            src_ip     = fields[_SRC_IP]
            src_port   = int(fields[_SRC_PORT])
            dst_ip     = fields[_DST_IP]
            dst_port   = int(fields[_DST_PORT])
            conn_state = fields[_CONN_STATE] if len(fields) > _CONN_STATE else "-"
            if self._assembler:
                self._assembler.attach_zeek_meta(
                    src_ip, dst_ip, src_port, dst_port, uid, conn_state
                )
        except (ValueError, IndexError):
            pass

    def _parse_ssl_line(self, line: str) -> None:
        # ssl.log: uid is field[1]; used for correlation only
        # TLS details are extracted by tshark_extractor, not Zeek ssl.log
        pass

    def _parse_dns_line(self, line: str) -> None:
        # dns.log enrichment is done directly by Scapy's DNS layer in flow_assembler
        pass

    def _stderr_drain(self) -> None:
        if not self._proc:
            return
        for raw in self._proc.stderr:
            log.debug("zeek_stderr", msg=raw.decode("utf-8", errors="replace").strip())

    def _health_monitor(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(5)
            alive = self.is_alive()
            ZEEK_ALIVE.set(1 if alive else 0)
            if not alive and not self._stop_event.is_set():
                log.error("zeek_process_died", returncode=self._proc.returncode)
