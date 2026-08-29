"""
processing/flow_assembler.py
============================
Stateful 5-tuple flow tracker.

Ingests individual packets (post-discard) and accumulates them into
FlowState objects keyed by (src_ip, dst_ip, src_port, dst_port, protocol).

Emits a complete FlowObject when:
  1. TCP FIN or RST observed → emit immediately
  2. Packet count >= FLOW_MAX_PACKETS → emit immediately (memory guard)
  3. Flow has been idle for FLOW_IDLE_TIMEOUT_S → background sweeper emits it

Thread-safety: all state mutations are inside a single threading.Lock().
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Tuple

import structlog

from config.settings import settings
from processing.flow_object import (
    DNSMeta, FiveTuple, FlowObject, TLSMeta,
)

log = structlog.get_logger()

# ── Type aliases ──────────────────────────────────────────────────────────────
FlowKey = Tuple[str, str, int, int, str]   # (src_ip, dst_ip, src_port, dst_port, proto)

# TCP flag bitmasks
_SYN = 0x02
_RST = 0x04
_FIN = 0x01
_ACK = 0x10
_PSH = 0x08
_URG = 0x20

# Ports that indicate TLS
_TLS_PORTS = {443, 8443, 4443, 9443}

# Max packet samples stored per flow (keeps FlowObject size bounded)
_MAX_SAMPLES = 50


# ── Internal flow state ───────────────────────────────────────────────────────

class FlowState:
    __slots__ = (
        "key", "flow_id", "first_seen", "last_seen",
        "packet_times", "sizes", "iat_list", "flags",
        "bytes_in", "tls_meta", "dns_meta",
        "zeek_uid", "zeek_conn_state",
    )

    def __init__(self, key: FlowKey, ts: float):
        self.key        = key
        self.flow_id    = str(uuid.uuid4())
        self.first_seen = ts
        self.last_seen  = ts
        self.packet_times: list[float] = [ts]
        self.sizes:     list[int]   = []
        self.iat_list:  list[float] = []
        self.flags:     set[str]    = set()
        self.bytes_in:  int         = 0
        self.tls_meta:  Optional[TLSMeta] = None
        self.dns_meta:  Optional[DNSMeta] = None
        self.zeek_uid:        Optional[str] = None
        self.zeek_conn_state: Optional[str] = None


# ── Flow Assembler ────────────────────────────────────────────────────────────

class FlowAssembler:
    """
    Thread-safe 5-tuple flow assembler.

    on_flow_complete: callback(FlowObject) — called every time a flow is closed.
                      Called from inside the lock, so must not block.
    """

    def __init__(self, on_flow_complete: Callable[[FlowObject], None]):
        self._flows: Dict[FlowKey, FlowState] = {}
        self._lock  = threading.Lock()
        self._on_complete = on_flow_complete
        self._sweeper_thread = self._start_sweeper()

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, pkt) -> None:
        """
        Process one packet. Called from Scapy's callback thread.
        Must be fast — any blocking here drops packets.
        """
        key = self._extract_key(pkt)
        if key is None:
            return

        ts      = float(pkt.time)
        pkt_len = len(pkt)

        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowState(key, ts)

            state = self._flows[key]

            # Inter-arrival time
            if len(state.packet_times) > 0:
                iat = ts - state.last_seen
                if len(state.iat_list) < _MAX_SAMPLES:
                    state.iat_list.append(round(iat, 6))

            state.last_seen = ts
            state.packet_times.append(ts)
            state.bytes_in += pkt_len
            if len(state.sizes) < _MAX_SAMPLES:
                state.sizes.append(pkt_len)

            # TCP flags
            emit_now = False
            if self._has_tcp(pkt):
                flags = int(pkt["TCP"].flags)
                decoded = self._decode_flags(flags)
                state.flags.update(decoded)
                # FIN or RST → close the flow immediately
                if (flags & _FIN) or (flags & _RST):
                    emit_now = True

            # DNS enrichment (UDP/53 or TCP/53)
            if self._has_dns(pkt):
                self._attach_dns(pkt, state)

            # Max-packet guard
            if len(state.packet_times) >= settings.flow_max_packets:
                emit_now = True

            if emit_now:
                self._emit(key, state)

    def attach_tls_meta(
        self,
        src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        tls_meta: TLSMeta,
    ) -> None:
        """Called by TsharkExtractor when a TLS ClientHello is parsed."""
        for proto in ("TCP/TLS", "TCP"):
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            with self._lock:
                if key in self._flows:
                    self._flows[key].tls_meta = tls_meta
                    return
        log.debug("tls_meta_no_matching_flow", src=src_ip, dst=dst_ip)

    def attach_zeek_meta(
        self,
        src_ip: str, dst_ip: str, src_port: int, dst_port: int,
        uid: str, conn_state: str,
    ) -> None:
        """Called by ZeekManager when a conn.log line is parsed."""
        for proto in ("TCP", "TCP/TLS", "UDP", "UDP/QUIC"):
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            with self._lock:
                if key in self._flows:
                    self._flows[key].zeek_uid        = uid
                    self._flows[key].zeek_conn_state = conn_state
                    return

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _extract_key(self, pkt) -> Optional[FlowKey]:
        try:
            if self._has_layer(pkt, "IP"):
                src_ip = pkt["IP"].src
                dst_ip = pkt["IP"].dst
            elif self._has_layer(pkt, "IPv6"):
                src_ip = pkt["IPv6"].src
                dst_ip = pkt["IPv6"].dst
            else:
                return None

            if self._has_tcp(pkt):
                sport = pkt["TCP"].sport
                dport = pkt["TCP"].dport
                proto = "TCP/TLS" if (sport in _TLS_PORTS or dport in _TLS_PORTS) else "TCP"
                return (src_ip, dst_ip, sport, dport, proto)

            elif self._has_layer(pkt, "UDP"):
                sport = pkt["UDP"].sport
                dport = pkt["UDP"].dport
                proto = "UDP/QUIC" if (sport == 443 or dport == 443) else "UDP"
                return (src_ip, dst_ip, sport, dport, proto)

            elif self._has_layer(pkt, "ICMP"):
                return (src_ip, dst_ip, 0, 0, "ICMP")

        except Exception as e:
            log.debug("flow_key_error", error=str(e))
        return None

    def _has_layer(self, pkt, name: str) -> bool:
        try:
            return pkt.haslayer(name)
        except Exception:
            return False

    def _has_tcp(self, pkt) -> bool:
        return self._has_layer(pkt, "TCP")

    def _has_dns(self, pkt) -> bool:
        return self._has_layer(pkt, "DNS")

    def _decode_flags(self, flags: int) -> list[str]:
        mapping = {_FIN: "F", _SYN: "S", _RST: "R", _PSH: "P", _ACK: "A", _URG: "U"}
        return [v for k, v in mapping.items() if flags & k]

    def _attach_dns(self, pkt, state: FlowState) -> None:
        try:
            dns = pkt["DNS"]
            if dns.qr == 0 and dns.qdcount > 0:   # it's a query, not a response
                qname = dns.qd.qname.decode("utf-8").rstrip(".")
                qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT",
                             10: "NULL", 12: "PTR", 33: "SRV"}
                qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))
                state.dns_meta = DNSMeta(
                    query_name   = qname,
                    query_type   = qtype,
                    query_length = len(qname),
                    answer_count = 0,
                )
        except Exception as e:
            log.debug("dns_parse_error", error=str(e))

    def _emit(self, key: FlowKey, state: FlowState) -> None:
        """Build FlowObject and fire callback. Removes state from dict. Must be called under lock."""
        try:
            del self._flows[key]
        except KeyError:
            return   # already emitted by sweeper race — safe to ignore

        src_ip, dst_ip, src_port, dst_port, proto = key

        flow = FlowObject(
            flow_id              = state.flow_id,
            first_seen           = datetime.fromtimestamp(state.first_seen, tz=timezone.utc),
            last_seen            = datetime.fromtimestamp(state.last_seen,  tz=timezone.utc),
            five_tuple           = FiveTuple(
                src_ip   = src_ip,
                dst_ip   = dst_ip,
                src_port = src_port,
                dst_port = dst_port,
                protocol = proto,
            ),
            duration_s           = round(state.last_seen - state.first_seen, 6),
            total_packets        = len(state.packet_times),
            total_bytes          = state.bytes_in,
            packet_sizes         = state.sizes,
            inter_arrival_times  = state.iat_list,
            tcp_flags_seen       = sorted(state.flags),
            bytes_in             = state.bytes_in,
            bytes_out_proxy      = 0,   # always 0 — cannot observe outbound under data diode
            tls_meta             = state.tls_meta,
            dns_meta             = state.dns_meta,
            zeek_conn_state      = state.zeek_conn_state,
            zeek_uid             = state.zeek_uid,
            sensor_id            = settings.sensor_id,
            capture_interface    = settings.capture_interface,
            pipeline_version     = settings.pipeline_version,
        )

        try:
            self._on_complete(flow)
        except Exception as e:
            log.error("flow_callback_error", flow_id=flow.flow_id, error=str(e))

    # ── Background sweeper ────────────────────────────────────────────────────

    def _start_sweeper(self) -> threading.Thread:
        def sweep():
            while True:
                time.sleep(10)
                now = time.time()
                expired_keys = []
                with self._lock:
                    for k, s in list(self._flows.items()):
                        if now - s.last_seen > settings.flow_idle_timeout_s:
                            expired_keys.append(k)
                for key in expired_keys:
                    with self._lock:
                        if key in self._flows:
                            self._emit(key, self._flows[key])
                log.debug("sweeper_run", expired=len(expired_keys), active=len(self._flows))

        t = threading.Thread(target=sweep, daemon=True, name="flow-sweeper")
        t.start()
        return t
