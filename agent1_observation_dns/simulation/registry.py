from .spec import PhaseSpec, ScenarioSpec
from .topology import topology


TRAINING_DURATION_S = {
    "benign_mixed": 1800, "ddos": 180, "port_scan": 300, "slow_scan": 1800,
    "dga": 600, "dns_tunnel": 900, "low_rate_dns_tunnel": 3600,
    "c2": 3600, "botnet": 1800, "encrypted_malware": 1800,
    "exfiltration": 900, "low_slow_exfiltration": 7200,
}


def training_scenario(family, *, scenario_id=None, seed=0, variant="default", environment="environment_A", split_assignment="train"):
    family = family.lower()
    duration = TRAINING_DURATION_S.get(family, 1800)
    scenario_id = scenario_id or f"{family}_{variant}_{seed:05d}"
    if family == "botnet":
        topology_name = "botnet_small"
    elif family in {"ddos", "load_test"}:
        topology_name = "load_test"
    else:
        topology_name = "enterprise_small"
    labels = {"dga": ("DGA",), "dns_tunnel": ("DNS_TUNNEL",), "low_rate_dns_tunnel": ("DNS_TUNNEL",),
              "c2": ("C2_BEACONING",), "botnet": ("BOTNET_HOST", "BOTNET_COORDINATION"),
              "encrypted_malware": ("ENCRYPTED_MALWARE",), "exfiltration": ("DATA_EXFILTRATION",),
              "low_slow_exfiltration": ("DATA_EXFILTRATION",), "ddos": ("DDoS",), "port_scan": ("PORT_SCAN",),
              "slow_scan": ("PORT_SCAN",)}.get(family, ())
    attack_start = min(60.0, duration / 4)
    phase = PhaseSpec("attack", attack_start, duration - 1, labels, (f"{family}_{variant}",)) if labels else None
    benign = ("dns_normal", "human_interactive", "machine_periodic", "bulk_transfer")
    return ScenarioSpec(scenario_id, duration, topology(topology_name), benign_profiles=benign,
                        attack_profiles=(f"{family}_{variant}",) if labels else (), seed=seed,
                        split_group=f"{family}:{variant}", split_assignment=split_assignment, environment=environment,
                        phases=(phase,) if phase else (), holdout_tags=(variant, family),
                        metadata={"generator_family": f"{family}_{variant}"})


SCENARIOS = {key: training_scenario(key) for key in TRAINING_DURATION_S}
