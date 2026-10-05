"""Optional local relying-party checkpoint freshness policy."""

from dataclasses import dataclass
import time


@dataclass(frozen=True)
class RPFreshnessPolicy:
    enabled: bool = False
    max_age_seconds: int = 300
    clock_skew_seconds: int = 60

    def __post_init__(self):
        if type(self.enabled) is not bool:
            raise ValueError("freshness policy enabled must be boolean")
        if (type(self.max_age_seconds) is not int
                or self.max_age_seconds < 0):
            raise ValueError("max_age_seconds must be a non-negative integer")
        if (type(self.clock_skew_seconds) is not int
                or self.clock_skew_seconds < 0):
            raise ValueError(
                "clock_skew_seconds must be a non-negative integer")


def check_checkpoint_freshness(timestamp, policy, now=None):
    """Apply optional local RP freshness policy to an authenticated timestamp."""
    if not isinstance(policy, RPFreshnessPolicy):
        raise ValueError("invalid RP freshness policy")

    if not policy.enabled:
        return

    if type(timestamp) is not int or timestamp <= 0:
        raise ValueError("timestamped checkpoint required by freshness policy")

    if now is None:
        now = int(time.time())
    if type(now) is not int or now < 0:
        raise ValueError("invalid current time")

    if timestamp > now + policy.clock_skew_seconds:
        raise ValueError("checkpoint timestamp is too far in the future")

    if now - timestamp > policy.max_age_seconds:
        raise ValueError("checkpoint timestamp is stale")
