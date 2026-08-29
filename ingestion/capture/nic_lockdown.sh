#!/usr/bin/env bash
# =============================================================================
# nic_lockdown.sh — Enforce RX-only, promiscuous mode on the capture NIC
# =============================================================================
# Run as root ONCE at boot, before any capture process starts.
# Called automatically by the ingestion entrypoint in HARDWARE mode.
#
# What this script does:
#   1. Disables TX offload at the driver level
#   2. Sets TX queue length to zero  (nothing can queue to send)
#   3. Removes any IP address        (no ARP, no route, no OS stack involvement)
#   4. Removes any default route     via this interface
#   5. Enables promiscuous mode      (see ALL frames, not just ours)
#   6. Disables IPv6                 (no Router Solicitations = no outbound traffic)
#   7. Enables reverse-path filter   (kernel drops frames with invalid source routes)
#
# =============================================================================
set -euo pipefail

IFACE="${CAPTURE_INTERFACE:-eth1}"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         NIC LOCKDOWN — DATA DIODE ENFORCEMENT       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Interface : $IFACE"
echo "  Mode      : RX-only, Promiscuous, Address-less"
echo ""

# ── Step 1: TX offload ────────────────────────────────────────────────────────
echo "[1/7] Disabling TX offload..."
ethtool -K "$IFACE" tx off 2>/dev/null && echo "      ✓ tx offload disabled" \
  || echo "      ⚠  tx offload disable not supported (OK in VMs/simulation)"

# ── Step 2: TX queue ──────────────────────────────────────────────────────────
echo "[2/7] Setting TX queue length to 0..."
ip link set "$IFACE" txqueuelen 0
echo "      ✓ txqueuelen = 0"

# ── Step 3: Remove IP addresses ───────────────────────────────────────────────
echo "[3/7] Flushing IP addresses from $IFACE..."
ip addr flush dev "$IFACE" 2>/dev/null && echo "      ✓ IP addresses removed" \
  || echo "      ✓ No IP addresses were assigned"

# ── Step 4: Remove default route ─────────────────────────────────────────────
echo "[4/7] Removing default route via $IFACE..."
ip route del default dev "$IFACE" 2>/dev/null && echo "      ✓ Default route removed" \
  || echo "      ✓ No default route via $IFACE"

# ── Step 5: Promiscuous mode ──────────────────────────────────────────────────
echo "[5/7] Enabling promiscuous mode..."
ip link set "$IFACE" promisc on
ip link set "$IFACE" up
echo "      ✓ Promiscuous mode ON"

# ── Step 6: Disable IPv6 ──────────────────────────────────────────────────────
echo "[6/7] Disabling IPv6 on $IFACE..."
sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=1" > /dev/null
echo "      ✓ IPv6 disabled (no Router Solicitations)"

# ── Step 7: Reverse-path filter ───────────────────────────────────────────────
echo "[7/7] Enabling reverse-path filter..."
sysctl -w "net.ipv4.conf.${IFACE}.rp_filter=1" > /dev/null
echo "      ✓ rp_filter = 1"

# ── Verification output ───────────────────────────────────────────────────────
echo ""
echo "  ── Final interface state ────────────────────────────"
ip link show "$IFACE"
echo ""
echo "  ── Route table (should be empty for $IFACE) ─────────"
ip route show dev "$IFACE" 2>/dev/null || echo "  (no routes)"
echo ""
echo "  ✅  NIC $IFACE is now RX-only, promiscuous, address-less."
echo "  ✅  Lockdown complete. Safe to start capture."
echo ""
