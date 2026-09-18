"""
capture/scapy_engine.py
=======================
Async, non-blocking Scapy packet capture engine.

Works in both modes:
  HARDWARE   — captures from real NIC (e.g. eth1)
  SIMULATION — captures from loopback (lo) or reads a .pcap file offline

Per-packet flow:
  raw frame → should_discard()? → FlowAssembler.ingest() → FlowObject → Redis
"""
from __future__ import annotations
import structlog
from config.settings import settings
from processing.discard import should_discard
from monitoring.metrics import PACKETS_CAPTURED, PACKETS_DISCARDED, PACKETS_PROCESSED

log = structlog.get_logger()


class ScapyEngine:
    """
    Wraps Scapy's AsyncSniffer.
    Caller provides a FlowAssembler instance; this engine feeds it packets.
    """

    def __init__(self, flow_assembler, interface: str = None, pcap_file: str = None):
        """
        interface:  NIC name to live-capture from (live / hardware mode)
        pcap_file:  path to .pcap for offline replay (simulation mode with pcap_file)
        If neither is set, falls back to settings values.
        """
        self._assembler  = flow_assembler
        self._interface  = interface or settings.capture_interface
        self._pcap_file  = pcap_file or settings.pcap_file_path
        self._mode       = settings.capture_mode
        self._sniffer    = None

    def start(self) -> None:
        from scapy.all import AsyncSniffer, sniff

        if self._mode == "pcap_file":
            if not self._pcap_file:
                raise ValueError("CAPTURE_MODE=pcap_file but PCAP_FILE_PATH is not set.")
            log.info("scapy_engine_pcap", file=self._pcap_file)
            # Offline replay — blocking, runs in a thread
            import threading
            t = threading.Thread(
                target=lambda: sniff(
                    offline  = self._pcap_file,
                    prn      = self._handle_packet,
                    store    = False,
                ),
                daemon = True,
                name   = "scapy-pcap-replay",
            )
            t.start()
        else:
            # Live capture (hardware NIC or loopback in simulation)
            iface = "lo" if self._mode == "loopback" else self._interface
            bpf_filter = None if iface in ("lo", "loopback") else "ip or ip6"
            log.info("scapy_engine_live", iface=iface, mode=self._mode, bpf_filter=bpf_filter)
            self._sniffer = AsyncSniffer(
                iface   = iface,
                filter  = bpf_filter,
                prn     = self._handle_packet,
                store   = False,         # CRITICAL: never buffer packets in RAM
                count   = 0,             # run forever
            )
            self._sniffer.start()
            log.info("scapy_sniffer_started", iface=iface)

    def stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            log.info("scapy_sniffer_stopped")

    def is_alive(self) -> bool:
        if self._sniffer is None:
            return False
        return self._sniffer.running

    # ── Private ────────────────────────────────────────────────────────────────

    def _handle_packet(self, pkt) -> None:
        """
        Called once per captured packet.
        This is the hot path — keep it fast, no I/O, no blocking.
        """
        PACKETS_CAPTURED.inc()

        # ── DISCARD GATE (must be first) ──────────────────────────────────────
        if should_discard(pkt):
            PACKETS_DISCARDED.inc()
            return   # packet is gone — nothing downstream sees it

        # ── Valid observation — send to flow assembler ─────────────────────────
        PACKETS_PROCESSED.inc()
        self._assembler.ingest(pkt)
