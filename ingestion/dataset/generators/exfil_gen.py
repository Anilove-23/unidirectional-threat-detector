"""
dataset/generators/exfil_gen.py
==============================
Generates simulated data exfiltration traffic by streaming high-volume,
large-MTU chunks to a target or local sink.

Threat Class: DATA_EXFILTRATION (SIH26145 §6 threat_class enum)

Usage:
  python exfil_gen.py --target 127.0.0.1 --port 8080 --duration 30
"""
import argparse
import os
import socket
import sys
import threading
import time


def _local_sink(port: int, stop_event: threading.Event):
    """Temporary local sink to accept connections if running on loopback."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        srv.settimeout(1.0)
        while not stop_event.is_set():
            try:
                conn, _ = srv.accept()
                conn.settimeout(1.0)
                while not stop_event.is_set():
                    data = conn.recv(65536)
                    if not data:
                        break
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()
    except Exception:
        pass


def run(target: str, port: int, duration: int, chunk_size: int = 1400, rate_kb: int = 1024):
    print(f"[exfil_gen] Scenario  : DATA_EXFILTRATION")
    print(f"[exfil_gen] Target    : {target}:{port}")
    print(f"[exfil_gen] Duration  : {duration}s")
    print(f"[exfil_gen] Chunk Size: {chunk_size} bytes")
    print(f"[exfil_gen] Target Rate: ~{rate_kb} KB/s")
    print(f"[exfil_gen] Starting exfiltration simulation...")

    stop_sink = threading.Event()
    sink_thread = None
    if target in ("127.0.0.1", "localhost"):
        sink_thread = threading.Thread(target=_local_sink, args=(port, stop_sink), daemon=True)
        sink_thread.start()
        time.sleep(0.2)

    start = time.time()
    total_bytes = 0
    payload = os.urandom(chunk_size)

    while time.time() - start < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target, port))
            # Stream large chunks
            conn_start = time.time()
            while time.time() - conn_start < min(5.0, duration - (time.time() - start)):
                s.sendall(payload)
                total_bytes += len(payload)
                # Rate limiting sleep
                delay = (chunk_size / (rate_kb * 1024))
                time.sleep(max(0.0001, delay))
            s.close()
        except (socket.error, ConnectionRefusedError, OSError):
            # If target refuses connection, continue attempt cycle
            time.sleep(0.5)
            continue

    if sink_thread:
        stop_sink.set()
        sink_thread.join(timeout=1.0)

    elapsed = max(0.001, time.time() - start)
    print(f"[exfil_gen] Done — Exfiltrated {total_bytes / 1024:.1f} KB in {elapsed:.1f}s ({total_bytes / (1024 * elapsed):.1f} KB/s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Data Exfiltration generator for SIH26145 dataset")
    parser.add_argument("--target",     default="127.0.0.1", help="Target IP address")
    parser.add_argument("--port",       type=int, default=8080, help="Target port")
    parser.add_argument("--duration",   type=int, default=10, help="Duration in seconds")
    parser.add_argument("--chunk-size", type=int, default=1400, help="Packet payload chunk size in bytes")
    parser.add_argument("--rate-kb",    type=int, default=512, help="Approx upload rate in KB/s")
    args = parser.parse_args()

    try:
        run(args.target, args.port, args.duration, args.chunk_size, args.rate_kb)
    except KeyboardInterrupt:
        print("\n[exfil_gen] Stopped by user.")
