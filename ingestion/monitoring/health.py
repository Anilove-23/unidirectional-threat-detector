"""
monitoring/health.py
====================
Lightweight Flask HTTP health endpoint.
  GET /health  → 200 {"status":"ok"} or 503 {"status":"degraded"}

Used by Docker HEALTHCHECK and external orchestration.
Runs in a daemon thread — does not block the capture loop.
"""
from __future__ import annotations
import threading
from flask import Flask, jsonify, Response
import structlog
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

log = structlog.get_logger()
app = Flask(__name__)

# Set by start_health_server — checked in the /health route
_redis_publisher = None
_zeek_manager    = None


@app.route("/health")
def health():
    redis_ok = False
    zeek_ok  = False

    if _redis_publisher:
        try:
            redis_ok = _redis_publisher.ping()
        except Exception:
            redis_ok = False

    if _zeek_manager:
        zeek_ok = _zeek_manager.is_alive()
    else:
        zeek_ok = True   # Zeek is not required in simulation mode

    overall = "ok" if (redis_ok and zeek_ok) else "degraded"
    code    = 200 if overall == "ok" else 503

    return jsonify({
        "status":  overall,
        "redis":   redis_ok,
        "zeek":    zeek_ok,
    }), code


@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


@app.route("/ping")
def ping():
    return jsonify({"pong": True}), 200


def start_health_server(redis_publisher, zeek_manager, port: int = 9101) -> None:
    global _redis_publisher, _zeek_manager
    _redis_publisher = redis_publisher
    _zeek_manager    = zeek_manager

    def _run():
        import logging
        log_flask = logging.getLogger('werkzeug')
        log_flask.setLevel(logging.ERROR)
        app.run(host="0.0.0.0", port=port, use_reloader=False, threaded=True)

    t = threading.Thread(target=_run, daemon=True, name="health-server")
    t.start()
    log.info("health_server_started", port=port, endpoints=["/health", "/metrics"])
