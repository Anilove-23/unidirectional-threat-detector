/**
 * Threat-class presentation helpers. Keeps the closed enum <-> human label
 * mapping in one place so no component free-texts a threat class name.
 */

export const THREAT_CLASS_LABELS = {
  VOLUMETRIC_DDOS: 'Volumetric DDoS',
  PORT_SCAN: 'Port Scan',
  DATA_EXFILTRATION: 'Data Exfiltration',
  DGA_DOMAIN: 'DGA Domain',
  DNS_TUNNELING: 'DNS Tunnelling',
  BOTNET_C2_BEACONING: 'Botnet C2 Beaconing',
  ANOMALOUS_UNCLASSIFIED: 'Anomalous / Unclassified',
};

// Short labels for tight spaces (filter chips, legends).
export const THREAT_CLASS_SHORT_LABELS = {
  VOLUMETRIC_DDOS: 'DDoS',
  PORT_SCAN: 'Port Scan',
  DATA_EXFILTRATION: 'Exfiltration',
  DGA_DOMAIN: 'DGA',
  DNS_TUNNELING: 'DNS Tunnel',
  BOTNET_C2_BEACONING: 'Botnet C2',
  ANOMALOUS_UNCLASSIFIED: 'Anomalous',
};

// One accent per threat class, used only for chart series — never overrides
// the severity color, which remains the primary urgency signal.
export const THREAT_CLASS_COLORS = {
  VOLUMETRIC_DDOS: '#E5484D',
  PORT_SCAN: '#5B8DEF',
  DATA_EXFILTRATION: '#F2994A',
  DGA_DOMAIN: '#B180F0',
  DNS_TUNNELING: '#2DD4BF',
  BOTNET_C2_BEACONING: '#E8C547',
  ANOMALOUS_UNCLASSIFIED: '#93A1B4',
};

export function threatClassLabel(threatClass) {
  return THREAT_CLASS_LABELS[threatClass] ?? threatClass;
}

export function threatClassShortLabel(threatClass) {
  return THREAT_CLASS_SHORT_LABELS[threatClass] ?? threatClass;
}

export function threatClassColor(threatClass) {
  return THREAT_CLASS_COLORS[threatClass] ?? '#93A1B4';
}

/**
 * Human-readable labels for evidence field keys. Any key not listed here
 * falls back to a generated label (see formatEvidenceKey) so new evidence
 * fields never disappear from the drill-down view.
 */
export const EVIDENCE_FIELD_LABELS = {
  ja3_fingerprint: 'JA3 Fingerprint',
  ja4_fingerprint: 'JA4 Fingerprint',
  beacon_interval_seconds: 'Beacon Interval',
  beacon_interval_jitter: 'Beacon Jitter',
  packet_size_sequence_sample: 'Packet Size Sequence',
  src_ip_entropy: 'Source IP Entropy',
  asymmetric_byte_ratio: 'Asymmetric Byte Ratio',
  cipher_suite_order_anomaly: 'Cipher Suite Order Anomaly',
  unique_dst_ports: 'Unique Destination Ports',
  syn_ratio: 'SYN Ratio',
  packets_per_second: 'Packets / Second',
  query_entropy: 'Query String Entropy',
  ngram_score: 'N-gram Anomaly Score',
  distinct_subdomains: 'Distinct Subdomains',
  query_length_mean: 'Mean Query Length',
  bytes_out_total: 'Total Bytes Out',
  bytes_in_total: 'Total Bytes In',
  unique_dst_ips: 'Unique Destination IPs',
  ttl_variance: 'TTL Variance',
};

export function formatEvidenceKey(key) {
  if (EVIDENCE_FIELD_LABELS[key]) return EVIDENCE_FIELD_LABELS[key];
  return key
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}
