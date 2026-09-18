"""
config/settings.py
All configuration loaded from environment variables / .env file.
Pydantic BaseSettings gives automatic env-var parsing + type validation.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Literal
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── NIC / capture ──────────────────────────────────────────────────────────
    capture_interface: str = Field("eth1", alias="CAPTURE_INTERFACE")
    capture_mode: Literal["live", "pcap_file", "loopback"] = Field(
        "live", alias="CAPTURE_MODE"
    )
    pcap_file_path: str = Field("", alias="PCAP_FILE_PATH")

    # ── Run mode (set by CLI launcher) ─────────────────────────────────────────
    run_mode: Literal["hardware", "simulation"] = Field(
        "simulation", alias="RUN_MODE"
    )

    # ── Redis ──────────────────────────────────────────────────────────────────
    redis_host: str = Field("127.0.0.1", alias="REDIS_HOST")
    redis_port: int = Field(6379, alias="REDIS_PORT")
    redis_channel_raw: str = Field("flow.raw", alias="REDIS_CHANNEL_RAW")
    redis_channel_health: str = Field("ingestion.health", alias="REDIS_CHANNEL_HEALTH")
    redis_publish_timeout_ms: int = Field(100, alias="REDIS_PUBLISH_TIMEOUT_MS")
    redis_max_queue_depth: int = Field(10000, alias="REDIS_MAX_QUEUE_DEPTH")

    # ── Zeek ───────────────────────────────────────────────────────────────────
    zeek_log_dir: str = Field("/tmp/zeek_logs", alias="ZEEK_LOG_DIR")
    zeek_scripts_dir: str = Field("ingestion/capture/config", alias="ZEEK_SCRIPTS_DIR")

    # ── Flow assembly ──────────────────────────────────────────────────────────
    flow_idle_timeout_s: int = Field(5, alias="FLOW_IDLE_TIMEOUT_S")
    flow_max_packets: int = Field(10000, alias="FLOW_MAX_PACKETS")

    # ── Sensor identity ────────────────────────────────────────────────────────
    sensor_id: str = Field("diode-sensor-01", alias="SENSOR_ID")
    pipeline_version: str = Field("1.0.0", alias="PIPELINE_VERSION")

    # ── Monitoring ─────────────────────────────────────────────────────────────
    metrics_port: int = Field(9101, alias="METRICS_PORT")
    log_level: str = Field("INFO", alias="LOG_LEVEL")


# Global singleton — import this everywhere
settings = Settings()
