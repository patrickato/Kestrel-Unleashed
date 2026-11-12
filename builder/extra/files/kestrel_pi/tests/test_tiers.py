from kestrel_pi.crack import tiers


def test_mask_keyspace_products_charset_sizes():
    assert tiers.mask_keyspace("?d?d?d?d?d?d?d?d") == 10 ** 8
    assert tiers.mask_keyspace("?d?d?d?d?d?d") == 10 ** 6
    assert tiers.mask_keyspace("?H?H?H?H?H?H?H?H") == 16 ** 8
    assert tiers.mask_keyspace("abc?d?d") == 10 ** 2        # literals are a factor of 1
    assert tiers.mask_keyspace("?a?a") == 95 ** 2


def test_mask_keyspace_unknown_for_a_custom_charset():
    # ?1-?4 are defined outside the mask, so the size can't be known here.
    assert tiers.mask_keyspace("?1?1?1?1") is None


def test_affordable_defers_the_8_digit_sweep_but_runs_a_small_mask():
    assert not tiers.affordable_on_pi("?d?d?d?d?d?d?d?d")   # 1e8: weeks on the Pi CPU
    assert tiers.affordable_on_pi("?d?d?d?d?d?d")           # 1e6: minutes
    assert not tiers.affordable_on_pi("?1?1?1?1")           # unknown size -> defer
    # Tunable: a GPU-less operator can raise the budget to grind more on-device.
    assert tiers.affordable_on_pi("?d?d?d?d?d?d?d?d", budget=10 ** 9)


def test_split_masks_partitions_by_budget():
    on_pi, deferred = tiers.split_masks(
        ["?d?d?d?d", "?d?d?d?d?d?d?d?d", "?H?H?H?H?H?H?H?H"])
    assert on_pi == ["?d?d?d?d"]
    assert deferred == ["?d?d?d?d?d?d?d?d", "?H?H?H?H?H?H?H?H"]
