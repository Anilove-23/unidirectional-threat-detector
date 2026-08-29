# local.zeek
# ==========
# Minimal passive-only Zeek configuration for SIH26145 ingestion sensor.
# Loads only the log modules needed; disables anything that could generate
# outbound/active traffic from the monitoring enclave.
#
# Loaded modules:
#   conn    → conn.log (5-tuple, bytes, duration, conn_state)
#   dns     → dns.log  (query names, types — needed for DGA/tunnel detection)
#   ssl     → ssl.log  (TLS version, server name — correlates with tshark JA3)
#   ja3     → ja3.log  (JA3 fingerprints from TLS ClientHello)
#
# Explicitly NOT loaded:
#   base/frameworks/notice/weird  — can generate ICMP unreachables
#   policy/frameworks/software    — does active version probing
#   policy/protocols/ssh          — can attempt active key exchange logging
#   Any Intel framework           — may do active lookups
#
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load policy/protocols/ssl/ja3

# Rotate logs every hour to keep file sizes manageable
redef Log::default_rotation_interval = 1hr;

# Do not try to resolve IP addresses to hostnames (that would be an outbound DNS query)
redef DNS::max_pending_queries = 0;

event zeek_init()
    {
    print fmt("[Zeek] Started in passive RX-only mode. Pipeline: %s", "SIH26145 v1.0.0");
    }
