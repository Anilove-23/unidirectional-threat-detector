import numpy as np
import pandas as pd
import pytest

from ..evaluation.cicids import forward_matrix


def test_cicids_mapping_uses_forward_duration_and_preserves_missing():
    frame = pd.DataFrame({"Total Fwd Packet": [3, 1], "Fwd IAT Total": [2000000, 0],
                          "Fwd IAT Mean": [1000000, 0], "Fwd IAT Min": [500000, 0],
                          "Fwd IAT Max": [1500000, 0], "Fwd PSH Flags": [1, 0],
                          "Fwd URG Flags": [0, 0], "Fwd RST Flags": [0, 0], "Protocol": [6, 17],
                          "Flow Duration": [99999999, 99999999], "Total Bwd packets": [200, 100],
                          "Label": ["BENIGN", "DDoS"]})
    paths = ["flow.packet_count", "flow.duration_s", "flow.pps", "flow.iat_s_mean", "flow.psh_count"]
    raw, valid, _, _ = forward_matrix(frame, paths)
    np.testing.assert_allclose(raw[0], [3, 2, 1.5, 1, 1])
    assert valid.all()
    assert np.isnan(raw[1, 2:]).all()
    frame["Label"] = "changed"
    frame["Flow Duration"] = 1
    frame["Total Bwd packets"] = 0
    np.testing.assert_allclose(raw, forward_matrix(frame, paths)[0], equal_nan=True)
    with pytest.raises(ValueError, match="unvalidated CICIDS"):
        forward_matrix(frame, ["flow.byte_count"])
