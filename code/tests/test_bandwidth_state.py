import json
from unittest.mock import patch

import pytest

from src.engine.bandwidth_state import BandwidthState, StateError


def test_assignments_survive_reopening(tmp_path):
    path = tmp_path / "state.json"

    with BandwidthState(path).locked() as transaction:
        assigned = transaction.reserve_host("172.30.50.20", 5)
        transaction.save()

    with BandwidthState(path).locked() as transaction:
        record = transaction.data["hosts"]["172.30.50.20"]
        assert record["class_id"] == assigned
        assert record["rate_mbps"] == 5
        assert record["phase"] == "pending"


def test_repeat_host_keeps_same_id(tmp_path):
    with BandwidthState(tmp_path / "state.json").locked() as transaction:
        first = transaction.reserve_host("172.30.50.20", 5)
        second = transaction.reserve_host("172.30.50.20", 10)

        assert first == second
        assert len(transaction.data["hosts"]) == 1
        assert transaction.data["hosts"]["172.30.50.20"]["rate_mbps"] == 10


def test_two_hosts_have_distinct_ids(tmp_path):
    with BandwidthState(tmp_path / "state.json").locked() as transaction:
        first = transaction.reserve_host("172.30.50.20", 5)
        second = transaction.reserve_host("172.30.50.30", 10)
        assert first != second


def test_unsaved_changes_are_not_persisted(tmp_path):
    path = tmp_path / "state.json"

    with BandwidthState(path).locked() as transaction:
        transaction.reserve_host("172.30.50.20", 5)

    assert not path.exists()


def test_corrupt_state_is_not_overwritten(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{broken JSON", encoding="utf-8")

    with pytest.raises(StateError):
        with BandwidthState(path).locked():
            pass

    assert path.read_text() == "{broken JSON"


def test_duplicate_ids_are_rejected(tmp_path):
    with BandwidthState(tmp_path / "state.json").locked() as transaction:
        transaction.reserve_host("172.30.50.20", 5)
        transaction.reserve_host("172.30.50.30", 10)

        hosts = transaction.data["hosts"]
        hosts["172.30.50.30"]["class_id"] = hosts["172.30.50.20"]["class_id"]

        with pytest.raises(StateError):
            transaction.save()


def test_failed_replace_preserves_previous_state(tmp_path):
    path = tmp_path / "state.json"

    with BandwidthState(path).locked() as transaction:
        transaction.reserve_host("172.30.50.20", 5)
        transaction.save()
        original = path.read_bytes()

        transaction.reserve_host("172.30.50.20", 10)

        with patch(
            "src.engine.bandwidth_state.os.replace",
            side_effect=OSError("simulated disk failure"),
        ):
            with pytest.raises(OSError):
                transaction.save()

        assert path.read_bytes() == original
        assert json.loads(path.read_text())["hosts"]["172.30.50.20"][
            "rate_mbps"
        ] == 5
