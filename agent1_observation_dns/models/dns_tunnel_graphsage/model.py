"""Optional graph branch contract. No untrained graph scores are emitted."""
from agent1_observation_dns.models.common import absent


class GraphBranch:
    name = "DNS_TUNNEL_GRAPHSAGE"

    def predict(self, event_id, domain, context=None):
        graph = (context or {}).get("graph")
        if not graph or not graph.get("sufficient"):
            return absent(event_id, self.name, "INSUFFICIENT_RELATION_VISIBILITY", applicable=False)
        return absent(event_id, self.name, "OPTIONAL_BRANCH_NOT_IMPLEMENTED")
