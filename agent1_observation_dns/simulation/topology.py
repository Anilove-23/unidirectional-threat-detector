from .spec import TopologySpec


TOPOLOGIES = {
    "minimal": TopologySpec("minimal", clients=1, servers=1, dns_servers=1, services=("web", "dns")),
    "enterprise_small": TopologySpec("enterprise_small", clients=6, servers=3, c2_nodes=1, dns_servers=1),
    "botnet_small": TopologySpec("botnet_small", clients=20, servers=6, c2_nodes=2, bot_hosts=6),
    "load_test": TopologySpec("load_test", clients=64, servers=12, c2_nodes=2, dns_servers=2),
}


def topology(name):
    try:
        return TOPOLOGIES[name]
    except KeyError as exc:
        raise ValueError(f"unknown topology: {name}") from exc
