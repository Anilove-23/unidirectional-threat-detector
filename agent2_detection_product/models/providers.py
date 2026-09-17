"""Runtime adapters for separately trained/calibrated specialist artifacts."""

import numpy as np
import torch
from .c2_periodicity import periodicity
from .encrypted_malware import early_sequence
from ..contracts import make_score, feature
from ..gating import gates


class C2Provider:
    def __init__(self, cthmm, temporal, fusion, calibrator, version):
        self.cthmm, self.temporal, self.fusion = cthmm, temporal, fusion
        self.calibrator, self.version = calibrator, version

    def score(self, envelope, context):
        timestamps = context["timestamps"]
        evidence = periodicity(timestamps)
        value = None
        if gates(envelope, context)["C2_BEACONING"]["ready"]:
            gaps = np.diff(timestamps)
            normalized = np.log1p(gaps).astype(np.float32)
            sequence = np.column_stack((normalized, np.ones(len(gaps), dtype=np.float32)))[None]
            self.temporal.eval()
            with torch.no_grad():
                temporal_score = float(torch.sigmoid(self.temporal(torch.as_tensor(sequence)))[0])
            ll = self.cthmm.log_likelihood(gaps) / len(gaps)
            values = [[evidence["iat_cv"], evidence["iat_mad"], evidence["spectral_concentration"], evidence["lag1_autocorrelation"], ll, temporal_score]]
            raw = self.fusion.predict(values)[0, 0]
            value = float(self.calibrator.predict([raw])[0])
            evidence.update({"cthmm_log_likelihood_per_event": ll, "temporal_score": temporal_score})
        score = make_score(envelope, "C2_BEACONING", value, "c2_fusion", self.version, calibrated=value is not None, evidence=evidence, reason="INSUFFICIENT_C2_HISTORY" if value is None else None)
        return {"scores": [score]}


def graph_arrays(edges):
    """Canonical graph training/inference representation; addresses only index."""
    nodes = sorted({node for source, dest, _ in edges for node in (source, dest)})
    index = {node: i for i, node in enumerate(nodes)}
    attributes = np.zeros((len(nodes), 4), dtype=np.float32)
    edge_index = []
    for source, dest, data in edges:
        s, d = index[source], index[dest]
        attributes[s, 0] += data["count"]
        # Bytes have their own observed count, preserving unavailable != zero.
        if data["bytes"] is not None:
            attributes[s, 1] += data["bytes"]
            attributes[s, 2] += 1
        attributes[d, 3] += 1
        edge_index.append((s, d))
    attributes = np.log1p(attributes)
    return nodes, attributes, np.asarray(edge_index, dtype=np.int64).reshape(-1, 2).T


class BotnetProvider:
    def __init__(self, gnn, tree, scaler, calibrators, version):
        self.gnn, self.tree, self.scaler = gnn, tree, scaler
        self.calibrators, self.version = calibrators, version

    def score(self, envelope, context):
        labels = ("BOTNET_HOST", "BOTNET_COORDINATION")
        ready = gates(envelope, context)["BOTNET_HOST"]["ready"]
        evidence = {"nodes": context["graph_nodes"], "edges": context["graph_edges"], "duration_seconds": context["graph_duration"]}
        values = [None, None]
        if ready:
            nodes, raw, edges = graph_arrays(context["graph"])
            x = self.scaler.transform(raw).astype(np.float32)
            self.gnn.eval()
            with torch.no_grad():
                embeddings = self.gnn.embed(torch.as_tensor(x), torch.as_tensor(edges)).numpy()
            index = nodes.index(envelope["entity_keys"]["source"])
            prediction = self.tree.predict(embeddings, x)[index]
            values = [float(self.calibrators[label].predict([prediction[i]])[0]) for i, label in enumerate(labels)]
        return {"scores": [make_score(envelope, label, values[i], "botnet_graph_tree", self.version, calibrated=ready, evidence=evidence, reason=None if ready else "INSUFFICIENT_GRAPH_HISTORY") for i, label in enumerate(labels)]}


class EncryptedProvider:
    def __init__(self, preprocessor, model, calibrator, version):
        self.preprocessor, self.model, self.calibrator, self.version = preprocessor, model, calibrator, version

    def score(self, envelope, context):
        gate = gates(envelope, context)["ENCRYPTED_MALWARE"]
        probability = None
        if gate["ready"]:
            values, masks = self.preprocessor.transform([envelope])
            sizes, _ = feature(envelope, "flow.packet_sizes")
            intervals, _ = feature(envelope, "flow.inter_arrival_times")
            stats = early_sequence(sizes or [], intervals or [])
            raw = self.model.predict(np.column_stack((values, masks, [stats])))[0, 0]
            probability = float(self.calibrator.predict([raw])[0])
        score = make_score(envelope, "ENCRYPTED_MALWARE", probability, "encrypted_metadata_sequence", self.version, calibrated=probability is not None, evidence={"packet_budget": 32, "payload_decrypted": False}, reason=None if probability is not None else gate["reason"])
        score["applicable"] = gate["applicable"]
        return {"scores": [score]}
