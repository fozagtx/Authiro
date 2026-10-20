"""Risk classification: override > annotation > verb > fail closed, plus escalation."""

from __future__ import annotations

import pytest

from authiro.risk import DESTRUCTIVE, READ, WRITE, RiskClassifier, args_hash


def test_override_wins_over_everything():
    c = RiskClassifier({"cloud_backup_*": WRITE})
    r = c.classify("cloud_backup_volume", name_for_verbs="backup_volume")
    assert (r.risk, r.source) == (WRITE, "override")


def test_override_rejects_unknown_risk():
    with pytest.raises(ValueError, match="must be one of"):
        RiskClassifier({"x": "chaotic"})


def test_annotation_readonly_and_destructive():
    c = RiskClassifier()
    assert c.classify("t", annotations={"readOnlyHint": True}).risk == READ
    assert c.classify("t", annotations={"destructiveHint": True}).risk == DESTRUCTIVE


def test_verb_classification():
    c = RiskClassifier()
    assert c.classify("cloud_delete_volume", name_for_verbs="delete_volume").risk == DESTRUCTIVE
    assert c.classify("cloud_get_status", name_for_verbs="get_status").risk == READ
    # run is a write verb: run_sql(SELECT) passes, DROP escalates
    assert c.classify("cloud_run_sql", name_for_verbs="run_sql").risk == WRITE


def test_strongest_verb_wins():
    c = RiskClassifier()
    # "delete" beats "get" when both appear
    assert c.classify("cloud_get_and_delete", name_for_verbs="get_and_delete").risk == DESTRUCTIVE


def test_unknown_tool_fails_closed_to_destructive():
    c = RiskClassifier()
    r = c.classify("cloud_zzz", name_for_verbs="zzz")
    assert (r.risk, r.source) == (DESTRUCTIVE, "default")


@pytest.mark.parametrize(
    ("payload", "detected"),
    [
        ("DROP TABLE users", True),
        ("drop database prod", True),
        ("TRUNCATE TABLE logs", True),
        ("TRUNCATE logs", True),
        ("DELETE FROM users WHERE 1=1", True),
        ("rm -rf /", True),
        ("SELECT * FROM users", False),
        ("INSERT INTO t VALUES (1)", False),
        ("update the docs please", False),
    ],
)
def test_argument_escalation(payload, detected):
    c = RiskClassifier()
    static = c.classify("cloud_run_sql", name_for_verbs="run_sql")
    assert static.risk == WRITE
    escalated = c.escalate({"sql": payload}, static)
    if detected:
        assert (escalated.risk, escalated.source) == (DESTRUCTIVE, "escalation")
    else:
        assert escalated.risk == WRITE


def test_escalation_scans_nested_args():
    c = RiskClassifier()
    static = c.classify("cloud_exec", name_for_verbs="exec")
    escalated = c.escalate({"payload": {"shell": ["rm", "-rf", "/"]}}, static)
    assert escalated.risk == DESTRUCTIVE


def test_escalation_never_lowers_destructive():
    c = RiskClassifier()
    static = c.classify("cloud_delete_volume", name_for_verbs="delete_volume")
    assert c.escalate({"sql": "SELECT 1"}, static).risk == DESTRUCTIVE


def test_args_hash_binds_exact_arguments():
    a = args_hash({"volume_id": "stg-db"})
    assert a == args_hash({"volume_id": "stg-db"})
    assert a != args_hash({"volume_id": "prod-db"})
    assert a != args_hash({"volume_id": "stg-db", "extra": None})
