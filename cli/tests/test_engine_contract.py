import pytest

from netra.engine import EngineError, _validate_event


def test_event_contract_rejects_wrong_request_id():
    with pytest.raises(EngineError, match="request_id"):
        _validate_event(
            {
                "protocol_version": "1.0",
                "request_id": "other",
                "type": "doctor.completed",
                "payload": {},
            },
            "expected",
        )


def test_event_contract_accepts_valid_event():
    _validate_event(
        {
            "protocol_version": "1.0",
            "request_id": "expected",
            "type": "doctor.completed",
            "payload": {},
        },
        "expected",
    )
