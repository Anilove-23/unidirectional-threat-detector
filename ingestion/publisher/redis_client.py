"""
publisher/redis_client.py
=========================
Fire-and-forget Redis PUBLISH wrapper.

Design constraints:
  ✅  Only ever calls redis.publish() — never subscribe(), get(), set(), xread()
  ✅  Failure is silent: RedisError → log + counter increment → continue
  ✅  No retry loop: retrying would block the capture callback and drop packets
  ✅  Mirrors the data-diode guarantee in software: we only ever push, never pull

This is the final step of Person 3's pipeline:
  FlowObject → serialize → PUBLISH to flow.raw
"""
from __future__ import annotations
import redis
import structlog
from config.settings import settings
from monitoring.metrics import REDIS_PUBLISH_LATENCY, REDIS_PUBLISH_ERRORS

log = structlog.get_logger()


class RedisPublisher:

    def __init__(self, in_memory: bool = False):
        self._in_memory = in_memory
        if in_memory:
            try:
                import fakeredis
                self._client = fakeredis.FakeRedis(decode_responses=True)
                log.info("redis_publisher_in_memory", msg="Using in-memory FakeRedis (zero-dependency mode)")
            except ImportError:
                self._client = None
        else:
            self._client = redis.Redis(
                host                 = settings.redis_host,
                port                 = settings.redis_port,
                socket_connect_timeout = 2,
                socket_timeout       = settings.redis_publish_timeout_ms / 1000,
                decode_responses     = True,
                protocol             = 2,
            )
        self._channel = settings.redis_channel_raw
        self._health_channel = settings.redis_channel_health

    def publish(self, flow_object) -> bool:
        """
        Serialize FlowObject to JSON and publish to flow.raw.
        Returns True on success, False on any failure.
        NEVER raises an exception.
        """
        try:
            with REDIS_PUBLISH_LATENCY.time():
                payload = flow_object.model_dump_json()
                self._client.publish(self._channel, payload)
            return True
        except redis.RedisError as e:
            REDIS_PUBLISH_ERRORS.inc()
            log.warning(
                "redis_publish_failed",
                error    = str(e),
                flow_id  = getattr(flow_object, "flow_id", "unknown"),
                channel  = self._channel,
            )
            return False
        except Exception as e:
            REDIS_PUBLISH_ERRORS.inc()
            log.error("redis_publish_unexpected_error", error=str(e))
            return False

    def publish_health(self, status: dict) -> None:
        """Publish a health heartbeat to ingestion.health channel."""
        try:
            import json
            self._client.publish(self._health_channel, json.dumps(status))
        except Exception:
            pass   # health publish failure is non-critical

    def ping(self) -> bool:
        """Returns True if Redis is reachable. Used by health endpoint."""
        try:
            return bool(self._client.ping())
        except redis.RedisError:
            return False
