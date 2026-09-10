import pytest

from src.tools.bandwidth import BandwidthService


@pytest.fixture
def snapshot():
    return (
        {
            "kind": "htb",
            "handle": "1:",
            "root": True,
        },
        [
            {
                "class": "htb",
                "handle": "1:1",
                "root": True,
                "rate": 625000,
                "ceil": 625000,
            }
        ],
        [
            {
                "protocol": "ip",
                "pref": 1,
                "kind": "flower",
                "chain": 0,
                "options": {
                    "handle": 1,
                    "classid": "1:1",
                    "keys": {
                        "eth_type": "ipv4",
                        "dst_ip": "172.30.50.20",
                    },
                },
            }
        ],
    )


@pytest.fixture
def record():
    return {"class_id": 1, "rate_mbps": 5.0, "phase": "pending"}


def test_fedora_rate_and_filter_verified(snapshot, record):
    service = BandwidthService()
    assert service._verified_limit(snapshot, "172.30.50.20", record)


def test_pending_assignment_recognized_as_owned(snapshot, record):
    service = BandwidthService()
    state = {
        "version": 1,
        "context": "test-context",
        "root_owned": True,
        "hosts": {"172.30.50.20": record},
    }
    assert service._check_ownership(state, snapshot, "test-context")


@pytest.mark.parametrize("field", ["rate", "ceil"])
def test_wrong_rate_or_ceiling_rejected(snapshot, record, field):
    snapshot[1][0][field] = 1250000
    assert not BandwidthService()._verified_limit(
        snapshot, "172.30.50.20", record
    )


def test_missing_rate_rejected(snapshot, record):
    del snapshot[1][0]["rate"]
    assert not BandwidthService()._verified_limit(
        snapshot, "172.30.50.20", record
    )


def test_wrong_destination_rejected(snapshot, record):
    snapshot[2][0]["options"]["keys"]["dst_ip"] = "172.30.50.30"
    assert not BandwidthService()._verified_limit(
        snapshot, "172.30.50.20", record
    )
