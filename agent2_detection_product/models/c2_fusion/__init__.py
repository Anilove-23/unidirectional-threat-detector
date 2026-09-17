from ..tabular_known_xgb import KnownXGBoost


class C2Fusion(KnownXGBoost):
    """Train on OOF periodicity, CT-HMM and temporal candidate outputs."""
    def __init__(self, **params):
        super().__init__(("C2_BEACONING",), **params)
