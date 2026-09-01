"""
dataset/generators/c2_beacon_gen.py
=====================================
Simulates Botnet C2 beaconing — low-and-slow periodic keep-alives.

Opens a TCP connection to target:port every (interval ± jitter) seconds,
sends a small fixed-size payload, then closes. This exactly matches the
traffic pattern Person 2's LSTM sequence model is trained to detect.

Key observable features this generates:
  - inter_arrival_times tightly clustered around `interval` seconds
  - packet_sizes: small, consistent (default 74 bytes)
  - tcp_flags: S, P, A, F per connection
  - high asymmetric_byte_ratio (tiny payload, no visible response)
  - dst_port = 443 (blend into HTTPS traffic)

Usage:
  python c2_beacon_gen.py --target 192.168.1.10 --interval 60 --duration 3600
"""
import argparse
import random
import socket
import ssl
import sys
import time


def beacon_loop(
    target:   str,
    port:     int,
    interval: float,
    jitter:   float,
    payload_size: int,
    duration: float,
    use_tls:  bool,
):
    print(f"[c2_beacon] Target   : {target}:{port}")
    print(f"[c2_beacon] Interval : {interval}s ± {jitter}s jitter")
    print(f"[c2_beacon] Payload  : {payload_size} bytes")
    print(f"[c2_beacon] TLS      : {'yes' if use_tls else 'no'}")
    print(f"[c2_beacon] Duration : {duration}s")
    print(f"[c2_beacon] Starting beacon loop...")

    start_time = time.time()
    beacon_count = 0

    while True:
        elapsed = time.time() - start_time
        if duration > 0 and elapsed >= duration:
            break

        sent_ok = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target, port))

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=target)

            payload = bytes([0xC2] * payload_size)
            sock.send(payload)
            sock.close()
            sent_ok = True
        except (socket.error, ssl.SSLError, OSError):
            # Fall back to Scapy raw packet injection onto the interface
            try:
                from scapy.all import IP, TCP, Raw, send
                sport = random.randint(30000, 60000)
                # Send SYN, then PSH+ACK with payload, then FIN
                p_syn = IP(dst=target)/TCP(sport=sport, dport=port, flags="S")
                p_data = IP(dst=target)/TCP(sport=sport, dport=port, flags="PA")/Raw(bytes([0xC2] * payload_size))
                p_fin = IP(dst=target)/TCP(sport=sport, dport=port, flags="FA")
                send([p_syn, p_data, p_fin], iface="lo" if target in ("127.0.0.1", "localhost") else None, verbose=False)
                sent_ok = True
            except Exception as ex:
                print(f"[c2_beacon] Failed to inject packet: {ex}")

        if sent_ok:
            beacon_count += 1
            print(f"[c2_beacon] Beacon #{beacon_count} sent ({payload_size}B) -> {target}:{port}  elapsed={elapsed:.1f}s")

        # Sleep for interval ± jitter
        sleep_time = interval + random.uniform(-jitter, jitter)
        sleep_time = max(0.1, sleep_time)
        time.sleep(sleep_time)

    print(f"[c2_beacon] Done — {beacon_count} beacons sent over {time.time() - start_time:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C2 beacon traffic generator for SIH26145 dataset")
    parser.add_argument("--target",       required=True,     help="Target IP or hostname")
    parser.add_argument("--port",         type=int, default=443,  help="Destination port")
    parser.add_argument("--interval",     type=float, default=60.0, help="Beacon interval in seconds")
    parser.add_argument("--jitter",       type=float, default=0.5,  help="±jitter in seconds")
    parser.add_argument("--payload-size", type=int, default=74,    help="Payload bytes per beacon")
    parser.add_argument("--duration",     type=float, default=0,   help="Total run seconds (0 = forever)")
    parser.add_argument("--tls",          action="store_true",      help="Wrap in TLS (self-signed)")
    args = parser.parse_args()

    try:
        beacon_loop(
            target       = args.target,
            port         = args.port,
            interval     = args.interval,
            jitter       = args.jitter,
            payload_size = args.payload_size,
            duration     = args.duration,
            use_tls      = args.tls,
        )
    except KeyboardInterrupt:
        print("\n[c2_beacon] Stopped by user.")
