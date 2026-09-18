"""
monitoring/metrics.py
=====================
Prometheus metrics for the ingestion pipeline.
Exposed at http://0.0.0.0:{METRICS_PORT}/metrics
"""
from prometheus_client import Counter, Histogram, Gauge, start_http_server
from config.settings import settings
import structlog

log = structlog.get_logger()

# ── Packet-level ──────────────────────────────────────────────────────────────
PACKETS_CAPTURED  = Counter(
    "ingestion_packets_captured_total",
    "Total packets seen on the capture interface"
)
PACKETS_DISCARDED = Counter(
    "ingestion_packets_discarded_total",
    "Packets dropped by the ACK/response discard logic"
)
PACKETS_PROCESSED = Counter(
    "ingestion_packets_processed_total",
    "Packets passed to the FlowAssembler after discard gate"
)

# ── Flow-level ────────────────────────────────────────────────────────────────
FLOWS_EMITTED = Counter(
    "ingestion_flows_emitted_total",
    "Complete FlowObjects emitted to Redis"
)
FLOWS_ACTIVE = Gauge(
    "ingestion_flows_active",
    "Flows currently held in the FlowAssembler state dict"
)

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_PUBLISH_LATENCY = Histogram(
    "ingestion_redis_publish_seconds",
    "Time taken to serialize and publish one FlowObject to Redis",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
REDIS_PUBLISH_ERRORS = Counter(
    "ingestion_redis_publish_errors_total",
    "Redis publish failures (timeout, connection error)"
)

# ── Subprocess health ─────────────────────────────────────────────────────────
ZEEK_ALIVE   = Gauge("ingestion_zeek_alive",   "1 if Zeek subprocess is running, 0 otherwise")
TSHARK_ALIVE = Gauge("ingestion_tshark_alive", "1 if tshark subprocess is running, 0 otherwise")


def start_metrics_server() -> None:
    """Metrics are served alongside /health on port 9101 via Flask."""
    pass
