import numpy as np
import pytest
import torch
from ..models.shared_ssl_encoder import MaskedPreprocessor, SSLEncoder
from ..models.c2_periodicity import periodicity
from ..models.c2_cthmm import ContinuousTimeHMM
from ..models.c2_temporal_tcn_gru import TemporalCandidate
from ..models.botnet_gnn import GraphSAGE
from ..models.meta_xgb import validate_oof, MetaXGBoost
from ..models.encrypted_malware import early_sequence
from ..calibration import select_threshold
from ..drift import distribution_drift
from ..evaluation.metrics import binary_metrics, report, routing_comparison
from ..evaluation.data import assert_disjoint
from .fixtures import envelope


def test_preprocessing_train_only_and_mask_preserved():
    env = envelope()
    preprocess = MaskedPreprocessor(["flow.byte_count", "dns.nxdomain_ratio"])
    with pytest.raises(ValueError):
        preprocess.fit([env], split="test")
    preprocess.fit([env], split="train")
    values, masks = preprocess.transform([env])
    assert masks.tolist() == [[1, 0]]
    model = SSLEncoder(2).fit(values, masks, split="train", epochs=1)
    assert model.embed(values, masks).shape == (1, 32)
    with pytest.raises(ValueError):
        MaskedPreprocessor(["flow.src_ip"])


def test_continuous_time_transition_and_periodicity():
    model = ContinuousTimeHMM()
    np.testing.assert_allclose(model.transition(0), np.eye(2))
    np.testing.assert_allclose(model.transition(17).sum(axis=1), 1)
    np.testing.assert_allclose(model.transition(10) @ model.transition(20), model.transition(30), atol=1e-8)
    assert np.isfinite(model.log_likelihood([10, 12, 8, 11]))
    evidence = periodicity([0, 10, 20, 30, 40, 50])
    assert evidence["periodicity_strength"] == 1
    assert periodicity([0, 1])["score_present"] is False


@pytest.mark.parametrize("kind", ["gru", "tcn"])
def test_temporal_candidates_ignore_right_padding(kind):
    torch.manual_seed(26)
    model = TemporalCandidate(kind=kind)
    sequence = torch.randn(1, 6, 2)
    padded = torch.cat((sequence, torch.randn(1, 3, 2)), dim=1)
    np.testing.assert_allclose(model(sequence).detach().numpy(), model(padded, torch.tensor([6])).detach().numpy(), atol=1e-6)


def test_graph_node_permutation_equivariance():
    torch.manual_seed(26)
    model = GraphSAGE(4)
    x = torch.randn(3, 4)
    edges = torch.tensor([[0, 1, 2], [1, 2, 0]])
    order = torch.tensor([2, 0, 1])
    inverse = torch.argsort(order)
    original = model(x, edges)
    permuted = model(x[order], inverse[edges])
    np.testing.assert_allclose(original[order].detach().numpy(), permuted.detach().numpy(), atol=1e-6)


def test_training_and_threshold_guards():
    with pytest.raises(ValueError):
        validate_oof([{"index": 0, "prediction_group": "a", "training_groups": ["a"], "split": "train"}], 1)
    with pytest.raises(ValueError):
        MetaXGBoost(["DDoS"]).fit([], [], split="train")
    with pytest.raises(ValueError):
        select_threshold([.1, .9], [0, 1], split="test")
    assert select_threshold([.1, .9], [0, 1], split="validation") == .9
    with pytest.raises(ValueError):
        select_threshold([.9, .1], [0, 1], split="validation")
    left = [{"scenario_id": "same", "group_id": "a", "observation": envelope()}]
    right = [{"scenario_id": "same", "group_id": "b", "observation": envelope("other")}]
    with pytest.raises(ValueError):
        assert_disjoint(left, right)


def test_encrypted_budget_and_metrics():
    assert early_sequence([1] * 32 + [999999], [2] * 32)[:3] == [1, 0, 1]
    assert binary_metrics([0, 1], [.1, .9])["roc_auc"] == 1
    assert distribution_drift([0] * 30, [100] * 30)["status"] == "SEVERE"
    assert not routing_comparison([{"DGA"}], [set()], [{"DGA"}])["gate_passed"]
