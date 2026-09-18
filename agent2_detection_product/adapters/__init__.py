"""Agent-1-to-Agent-2 consumer adapters.

Agent 1 owns the producer representation. These adapters unwrap it only at the
consumer boundary and retain all masks/reason codes alongside model values.
"""

from .observation_adapter import AdaptedObservation, adapt_observation, unwrap_measurement
from .schema_checks import check_observation_versions

__all__ = ["AdaptedObservation", "adapt_observation", "unwrap_measurement", "check_observation_versions"]
