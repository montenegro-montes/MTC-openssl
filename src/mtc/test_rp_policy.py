"""Focused deterministic tests for the optional local RP freshness policy."""

from rp_policy import RPFreshnessPolicy, check_checkpoint_freshness


NOW = 1_800_000_000


def rejected(function):
    try:
        function()
    except ValueError:
        return
    raise AssertionError("invalid freshness state accepted")


def main():
    disabled = RPFreshnessPolicy(enabled=False)

    # Disabled preserves the current behaviour, including timestamps that
    # would otherwise be stale, future, or unavailable.
    check_checkpoint_freshness(NOW - 10_000, disabled, NOW)
    check_checkpoint_freshness(NOW + 10_000, disabled, NOW)
    check_checkpoint_freshness(0, disabled, NOW)

    enabled = RPFreshnessPolicy(
        enabled=True,
        max_age_seconds=300,
        clock_skew_seconds=60,
    )

    # Current and exact boundaries are accepted.
    check_checkpoint_freshness(NOW, enabled, NOW)
    check_checkpoint_freshness(NOW - 299, enabled, NOW)
    check_checkpoint_freshness(NOW - 300, enabled, NOW)
    check_checkpoint_freshness(NOW + 60, enabled, NOW)

    # One second beyond either boundary is rejected.
    rejected(
        lambda: check_checkpoint_freshness(NOW - 301, enabled, NOW))
    rejected(
        lambda: check_checkpoint_freshness(NOW + 61, enabled, NOW))

    # Freshness requires a timestamped checkpoint.
    rejected(lambda: check_checkpoint_freshness(0, enabled, NOW))

    # Invalid policy configuration fails closed.
    for value in (-1, True, 1.5, "300"):
        rejected(lambda value=value: RPFreshnessPolicy(
            enabled=True,
            max_age_seconds=value,
            clock_skew_seconds=60,
        ))

    for value in (-1, True, 1.5, "60"):
        rejected(lambda value=value: RPFreshnessPolicy(
            enabled=True,
            max_age_seconds=300,
            clock_skew_seconds=value,
        ))

    rejected(lambda: RPFreshnessPolicy(enabled="enabled"))

    print("RP checkpoint freshness policy tests PASS")


if __name__ == "__main__":
    main()
