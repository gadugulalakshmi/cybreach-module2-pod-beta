from ve_app.time_window import filter_results_in_window


def test_overlapping_time_windows_keep_results_for_both_attacks():
    attack_1_timestamp = "2026-06-17T09:12:00Z"
    attack_2_timestamp = "2026-06-17T09:14:00Z"

    results = [
        {
            "observable": "attack-1-event",
            "timestamp": "2026-06-17T09:12:30Z",
        },
        {
            "observable": "overlapping-event",
            "timestamp": "2026-06-17T09:13:00Z",
        },
        {
            "observable": "attack-2-event",
            "timestamp": "2026-06-17T09:14:30Z",
        },
    ]

    attack_1_results = filter_results_in_window(
        attack_1_timestamp,
        results,
        window_seconds=120,
    )

    attack_2_results = filter_results_in_window(
        attack_2_timestamp,
        results,
        window_seconds=120,
    )

    assert any(
        result["observable"] == "overlapping-event"
        for result in attack_1_results
    )

    assert any(
        result["observable"] == "overlapping-event"
        for result in attack_2_results
    )


def test_overlapping_windows_do_not_include_distant_events():
    evidence_timestamp = "2026-06-17T09:12:00Z"

    results = [
        {
            "observable": "near-event",
            "timestamp": "2026-06-17T09:13:00Z",
        },
        {
            "observable": "distant-event",
            "timestamp": "2026-06-17T10:00:00Z",
        },
    ]

    filtered = filter_results_in_window(
        evidence_timestamp,
        results,
        window_seconds=120,
    )

    assert len(filtered) == 1
    assert filtered[0]["observable"] == "near-event"