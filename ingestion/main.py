"""
main.py — SIH26145 Ingestion Engine Launcher
=============================================
Presents an interactive terminal menu at startup so the operator
can choose exactly how the pipeline runs.

  ┌─────────────────────────────────────────────────┐
  │  Run Mode                                       │
  │  [1] HARDWARE   — real NIC, data diode           │
  │  [2] SIMULATION — loopback / software only       │
  │  [3] PCAP REPLAY — offline .pcap file            │
  │  [4] DATASET    — generate labeled training data │
  │  [5] TEST       — run unit + integration tests   │
  │  [q] Quit                                        │
  └─────────────────────────────────────────────────┘

All modes share the same capture → discard → assemble → publish pipeline.
The only difference is WHERE packets come from and whether NIC lockdown runs.
"""
from __future__ import annotations

import os
import sys
import time
import threading
import signal
import datetime

# ── Rich terminal UI ──────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    from rich.live    import Live
    from rich.text    import Text
    from rich         import box
    _RICH = True
except ImportError:
    _RICH = False

console = Console() if _RICH else None


# ═══════════════════════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    if _RICH:
        console.print(Panel(
            "[bold cyan]SIH26145[/bold cyan]  ·  AI-Based Detection of Cyber Threats\n"
            "[dim]Person 3 — Data Ingestion & Packet Processing Engine[/dim]\n"
            "[dim]National Technical Research Organisation (NTRO) · v1.0.0[/dim]",
            title="[bold white]THREAT DETECTION — INGESTION LAYER[/bold white]",
            border_style="cyan",
            padding=(1, 4),
        ))
    else:
        print("=" * 62)
        print("  SIH26145 — Threat Detection Ingestion Engine")
        print("  Person 3 · Data Ingestion & Packet Processing")
        print("=" * 62)


# ═══════════════════════════════════════════════════════════════════════════════
# Main menu
# ═══════════════════════════════════════════════════════════════════════════════

def show_menu() -> str:
    if _RICH:
        table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
        table.add_column("Key",   style="bold yellow", width=6)
        table.add_column("Mode",  style="bold white",  width=18)
        table.add_column("Description")

        table.add_row(
            "[1]", "HARDWARE",
            "[green]Real NIC + data diode / optical splitter[/green]\n"
            "[dim]Runs nic_lockdown.sh (requires root). "
            "Captures on eth1 (or configured CAPTURE_INTERFACE).[/dim]"
        )
        table.add_row(
            "[2]", "SIMULATION",
            "[yellow]Software only — no NIC changes[/yellow]\n"
            "[dim]Captures on loopback (lo). Safe to run as non-root, "
            "on any machine including Windows via WSL.[/dim]"
        )
        table.add_row(
            "[3]", "PCAP REPLAY",
            "[blue]Offline .pcap file replay[/blue]\n"
            "[dim]Reads a .pcap file through the full discard → assemble "
            "→ publish pipeline. No live interface needed.[/dim]"
        )
        table.add_row(
            "[4]", "DATASET",
            "[magenta]Generate labeled training data[/magenta]\n"
            "[dim]Runs attack/benign traffic generators (hping3, Slowloris, "
            "dnscat2, DGA, C2 beacon) and exports flows_labeled.csv.[/dim]"
        )
        table.add_row(
            "[5]", "TEST",
            "[cyan]Run unit + integration tests[/cyan]\n"
            "[dim]pytest tests/ — validates discard logic, flow assembly, "
            "and Redis publish. No capture interface needed.[/dim]"
        )
        table.add_row("[q]", "Quit", "[dim]Exit[/dim]")

        console.print("\n")
        console.print(Panel(table, title="[bold]Select Run Mode[/bold]", border_style="blue"))
        console.print("\n")
        choice = console.input("[bold yellow]Enter choice [1/2/3/4/5/q]:[/bold yellow] ").strip().lower()
    else:
        print("\n  Select Run Mode:\n")
        print("  [1] HARDWARE   — Real NIC + data diode (requires root)")
        print("  [2] SIMULATION — Loopback / software only (no root needed)")
        print("  [3] PCAP REPLAY — Offline .pcap file")
        print("  [4] DATASET    — Generate labeled training data")
        print("  [5] TEST       — Run unit + integration tests")
        print("  [q] Quit\n")
        choice = input("  Enter choice: ").strip().lower()

    return choice


# ═══════════════════════════════════════════════════════════════════════════════
# Mode handlers
# ═══════════════════════════════════════════════════════════════════════════════

def run_hardware_mode():
    """
    HARDWARE MODE
    =============
    - Checks for root
    - Runs nic_lockdown.sh to harden the capture NIC
    - Starts Zeek, tshark, Scapy on the real capture interface
    - Publishes FlowObjects to Redis
    """
    _print_mode_header("HARDWARE", "Real NIC capture with data-diode enforcement", "green")

    if os.geteuid() != 0:
        _err("HARDWARE mode requires root (sudo). Re-run with: sudo python main.py")
        sys.exit(1)

    # ── Confirm ───────────────────────────────────────────────────────────────
    from config.settings import settings
    iface = settings.capture_interface

    if _RICH:
        console.print(f"\n  [bold]Capture interface:[/bold] [cyan]{iface}[/cyan]")
        console.print(f"  [bold]Redis:[/bold] [cyan]{settings.redis_host}:{settings.redis_port}[/cyan]")
        console.print(f"  [bold]Sensor ID:[/bold] [cyan]{settings.sensor_id}[/cyan]\n")
        confirm = console.input("  [yellow]Run NIC lockdown on[/yellow] "
                                f"[bold]{iface}[/bold] [yellow]and start capture? [y/N]:[/yellow] ")
    else:
        print(f"\n  Capture interface : {iface}")
        print(f"  Redis             : {settings.redis_host}:{settings.redis_port}")
        confirm = input(f"\n  Run NIC lockdown on {iface} and start capture? [y/N]: ")

    if confirm.strip().lower() != "y":
        _info("Aborted.")
        return

    # ── NIC lockdown ──────────────────────────────────────────────────────────
    _info("Running NIC lockdown...")
    lockdown_script = os.path.join(os.path.dirname(__file__), "capture", "nic_lockdown.sh")
    ret = os.system(f"bash {lockdown_script}")
    if ret != 0:
        _err(f"nic_lockdown.sh failed (exit {ret}). Aborting.")
        sys.exit(1)

    # ── Override settings for hardware mode ───────────────────────────────────
    os.environ["CAPTURE_MODE"] = "live"
    os.environ["RUN_MODE"]     = "hardware"

    _start_pipeline(zeek_mode="live", tshark_iface=iface, scapy_iface=iface)


def run_simulation_mode():
    """
    SIMULATION MODE
    ===============
    - No NIC changes
    - Captures on loopback (lo) or configured interface
    - Identical discard → assemble → publish pipeline
    - Safe to run as non-root, on laptops, in CI
    """
    _print_mode_header("SIMULATION", "Software-only capture on loopback", "yellow")

    from config.settings import settings

    if _RICH:
        console.print("  [dim]No NIC changes will be made.[/dim]")
        console.print("  [dim]Packets will be captured from the [bold]loopback[/bold] interface.[/dim]")
        console.print(f"  [dim]Tip: In another terminal run:[/dim] [bold]python dataset/generators/c2_beacon_gen.py --target 127.0.0.1[/bold]\n")
    else:
        print("  No NIC changes. Capturing on loopback.")
        print("  Tip: In another terminal run: python dataset/generators/c2_beacon_gen.py --target 127.0.0.1\n")

    os.environ["CAPTURE_MODE"]      = "loopback"
    os.environ["CAPTURE_INTERFACE"] = "lo"
    os.environ["RUN_MODE"]          = "simulation"

    _start_pipeline(zeek_mode="disabled", tshark_iface="lo", scapy_iface="lo")


def run_pcap_mode():
    """
    PCAP REPLAY MODE
    ================
    - No live interface needed
    - Reads a .pcap file through the full pipeline
    - Publishes resulting FlowObjects to Redis
    """
    _print_mode_header("PCAP REPLAY", "Offline .pcap file replay", "blue")

    if _RICH:
        pcap_path = console.input("  [bold]Path to .pcap file:[/bold] ").strip()
    else:
        pcap_path = input("  Path to .pcap file: ").strip()

    if not os.path.isfile(pcap_path):
        _err(f"File not found: {pcap_path}")
        return

    os.environ["CAPTURE_MODE"]  = "pcap_file"
    os.environ["PCAP_FILE_PATH"] = pcap_path
    os.environ["RUN_MODE"]      = "simulation"

    _start_pipeline(zeek_mode="offline", tshark_iface=None, scapy_iface=None, pcap_file=pcap_path)


def run_dataset_mode():
    """
    DATASET GENERATION MODE
    =======================
    Shows a sub-menu of attack scenarios to run.
    """
    _print_mode_header("DATASET", "Generate labeled training data", "magenta")

    if _RICH:
        console.print("""
  [bold]Available scenarios:[/bold]

  [1] benign          — iperf3 normal TCP/UDP traffic
  [2] ddos            — hping3 SYN / UDP / ICMP flood
  [3] slowloris       — Slow HTTP header exhaustion
  [4] port_scan       — hping3 sequential SYN sweep
  [5] dns_tunnel      — dnscat2 DNS tunnelling
  [6] dga             — DGA domain generation (Conficker + Cryptolocker)
  [7] c2_beacon       — Periodic C2 keep-alive (60 s interval)
  [all] Run all scenarios in sequence
  [q] Back
        """)
        scenario = console.input("  [yellow]Choose scenario:[/yellow] ").strip().lower()
    else:
        print("\n  Scenarios: benign / ddos / slowloris / port_scan / dns_tunnel / dga / c2_beacon / all / q")
        scenario = input("  Choose: ").strip().lower()

    if scenario == "q":
        return

    if _RICH:
        target = console.input("  [bold]Target IP (default 127.0.0.1):[/bold] ").strip() or "127.0.0.1"
        duration = console.input("  [bold]Duration in seconds (default 30):[/bold] ").strip() or "30"
    else:
        target   = input("  Target IP [127.0.0.1]: ").strip() or "127.0.0.1"
        duration = input("  Duration seconds [30]: ").strip() or "30"

    _run_generator(scenario, target, int(duration))


def run_test_mode():
    """
    TEST MODE
    =========
    Runs pytest. No capture interface needed.
    """
    _print_mode_header("TEST", "Unit + Integration tests", "cyan")
    _info("Running pytest tests/...")
    ret = os.system(f"{sys.executable} -m pytest tests/ -v --tb=short")
    if ret == 0:
        _ok("All tests passed.")
    else:
        _err("Some tests failed. See output above.")


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline startup (shared by HARDWARE, SIMULATION, PCAP modes)
# ═══════════════════════════════════════════════════════════════════════════════

def _start_pipeline(
    zeek_mode:   str,
    tshark_iface: str | None,
    scapy_iface:  str | None,
    pcap_file:   str = "",
):
    """Wire up and start all ingestion components."""

    # Reload settings after env overrides
    from importlib import reload
    import config.settings as _cfg_mod
    reload(_cfg_mod)
    from config.settings import settings

    from processing.flow_assembler  import FlowAssembler
    from publisher.redis_client     import RedisPublisher
    from capture.zeek_manager       import ZeekManager
    from capture.tshark_extractor   import TsharkExtractor
    from capture.scapy_engine       import ScapyEngine
    from monitoring.metrics         import start_metrics_server, FLOWS_EMITTED, FLOWS_ACTIVE
    from monitoring.health          import start_health_server

    # ── Redis publisher ───────────────────────────────────────────────────────
    publisher = RedisPublisher()
    if not publisher.ping():
        if os.environ.get("RUN_MODE") == "simulation" or settings.run_mode == "simulation":
            _info("Real Redis not running. Falling back to In-Memory Mode (FakeRedis)...")
            publisher = RedisPublisher(in_memory=True)
            _ok("In-Memory Redis active (zero external dependencies required).")
        else:
            _err(f"Cannot connect to Redis at {settings.redis_host}:{settings.redis_port}")
            _err("Start Redis with: docker run -p 6379:6379 redis:7-alpine")
            sys.exit(1)
    else:
        _ok("Redis connected.")

    # ── Flow callback ─────────────────────────────────────────────────────────
    def on_flow_complete(flow):
        ok = publisher.publish(flow)
        FLOWS_EMITTED.inc()
        if _RICH:
            status = "[green]✓[/green]" if ok else "[red]✗[/red]"
            console.print(
                f"  {status} flow [{flow.five_tuple.protocol}] "
                f"{flow.five_tuple.src_ip}:{flow.five_tuple.src_port} → "
                f"{flow.five_tuple.dst_ip}:{flow.five_tuple.dst_port}  "
                f"pkts={flow.total_packets}  "
                f"bytes={flow.total_bytes}  "
                f"dur={flow.duration_s:.3f}s"
            )
        else:
            tag = "OK" if ok else "ERR"
            print(f"  [{tag}] flow {flow.five_tuple.src_ip}:{flow.five_tuple.src_port}"
                  f" → {flow.five_tuple.dst_ip}:{flow.five_tuple.dst_port}"
                  f" pkts={flow.total_packets}")

    # ── Assembler ─────────────────────────────────────────────────────────────
    assembler = FlowAssembler(on_flow_complete=on_flow_complete)

    # ── Zeek ──────────────────────────────────────────────────────────────────
    zeek = ZeekManager(flow_assembler=assembler)
    zeek.start(mode=zeek_mode, pcap_file=pcap_file)

    # ── tshark ────────────────────────────────────────────────────────────────
    tshark = TsharkExtractor(flow_assembler=assembler)
    if tshark_iface or pcap_file:
        tshark.start(iface=tshark_iface or "")

    # ── Scapy ─────────────────────────────────────────────────────────────────
    scapy = ScapyEngine(
        flow_assembler = assembler,
        interface      = scapy_iface or settings.capture_interface,
        pcap_file      = pcap_file,
    )
    scapy.start()

    # ── Monitoring ────────────────────────────────────────────────────────────
    start_metrics_server()
    start_health_server(publisher, zeek, port=settings.metrics_port)

    _ok("Pipeline started.")
    if _RICH:
        console.print(f"\n  [dim]Metrics + health: http://localhost:{settings.metrics_port}/health[/dim]")
        console.print(f"  [dim]Redis channel:     {settings.redis_channel_raw}[/dim]")
        console.print(f"  [dim]Press Ctrl+C to stop.[/dim]\n")
    else:
        print(f"\n  Health: http://localhost:{settings.metrics_port}/health")
        print("  Press Ctrl+C to stop.\n")

    # ── Health heartbeat ──────────────────────────────────────────────────────
    def heartbeat():
        while True:
            time.sleep(30)
            FLOWS_ACTIVE.set(assembler.active_flow_count())
            publisher.publish_health({
                "status":    "ok",
                "sensor_id": settings.sensor_id,
                "ts":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "active_flows": assembler.active_flow_count(),
            })

    threading.Thread(target=heartbeat, daemon=True, name="heartbeat").start()

    # ── Graceful shutdown on Ctrl+C ───────────────────────────────────────────
    def _shutdown(sig, frame):
        print("\n\n  Shutting down...")
        scapy.stop()
        tshark.stop()
        zeek.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Live stats display ────────────────────────────────────────────────────
    _run_live_stats(assembler)


def _run_live_stats(assembler):
    """Block the main thread showing live stats. Ctrl+C is handled by signal."""
    if not _RICH:
        while True:
            time.sleep(5)
        return

    from monitoring.metrics import (
        PACKETS_CAPTURED, PACKETS_DISCARDED, PACKETS_PROCESSED, FLOWS_EMITTED
    )

    with Live(console=console, refresh_per_second=1, screen=False) as live:
        while True:
            table = Table(title="Live Pipeline Stats", box=box.SIMPLE, min_width=50)
            table.add_column("Metric",  style="cyan")
            table.add_column("Value",   style="bold white", justify="right")

            def _cval(counter):
                try:
                    return str(int(counter._value.get()))
                except Exception:
                    return "—"

            table.add_row("Packets captured",  _cval(PACKETS_CAPTURED))
            table.add_row("Packets discarded", _cval(PACKETS_DISCARDED))
            table.add_row("Packets processed", _cval(PACKETS_PROCESSED))
            table.add_row("Flows emitted",     _cval(FLOWS_EMITTED))
            table.add_row("Active flows",       str(assembler.active_flow_count()))
            table.add_row("Uptime",             _uptime())

            live.update(table)
            time.sleep(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset generator runner
# ═══════════════════════════════════════════════════════════════════════════════

def _run_generator(scenario: str, target: str, duration: int):
    import subprocess as sp

    gen_dir = os.path.join(os.path.dirname(__file__), "dataset", "generators")
    mapping = {
        "benign":     "benign_gen.py",
        "ddos":       "ddos_gen.py",
        "slowloris":  "slowloris_gen.py",
        "port_scan":  "scan_gen.py",
        "dns_tunnel": "dns_tunnel_gen.py",
        "dga":        "dga_gen.py",
        "c2_beacon":  "c2_beacon_gen.py",
    }

    scenarios_to_run = list(mapping.items()) if scenario == "all" else \
                       [(scenario, mapping.get(scenario, ""))]

    for name, fname in scenarios_to_run:
        if not fname:
            _err(f"Unknown scenario: {name}")
            continue
        script = os.path.join(gen_dir, fname)
        if not os.path.isfile(script):
            _err(f"Generator not found: {script}")
            continue
        _info(f"Running scenario: {name} for {duration}s → target {target}")
        sp.run(
            [sys.executable, script, "--target", target, "--duration", str(duration)],
            timeout=duration + 10,
        )
        _ok(f"Scenario {name} complete.")
        time.sleep(2)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

_START_TIME = time.time()

def _uptime() -> str:
    elapsed = int(time.time() - _START_TIME)
    h, rem  = divmod(elapsed, 3600)
    m, s    = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def _print_mode_header(mode: str, desc: str, color: str):
    if _RICH:
        console.print(f"\n  ▶  Running in [bold {color}]{mode}[/bold {color}] mode — {desc}\n")
    else:
        print(f"\n  >> {mode} mode — {desc}\n")

def _info(msg: str):
    if _RICH: console.print(f"  [dim]{msg}[/dim]")
    else: print(f"  {msg}")

def _ok(msg: str):
    if _RICH: console.print(f"  [bold green]✓[/bold green]  {msg}")
    else: print(f"  [OK] {msg}")

def _err(msg: str):
    if _RICH: console.print(f"  [bold red]✗[/bold red]  {msg}")
    else: print(f"  [ERR] {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    while True:
        choice = show_menu()

        if choice == "1":
            run_hardware_mode()
        elif choice == "2":
            run_simulation_mode()
        elif choice == "3":
            run_pcap_mode()
        elif choice == "4":
            run_dataset_mode()
        elif choice == "5":
            run_test_mode()
        elif choice in ("q", "quit", "exit"):
            if _RICH:
                console.print("\n  [dim]Goodbye.[/dim]\n")
            else:
                print("\n  Goodbye.\n")
            sys.exit(0)
        else:
            _err(f"Invalid choice: '{choice}'. Enter 1–5 or q.")


if __name__ == "__main__":
    main()
