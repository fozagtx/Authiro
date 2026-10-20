"""Gate ledger tamper-evidence: edit, delete, reorder, truncate, forged head."""

from __future__ import annotations

import json

from authiro.ledger import (
    GateLedger,
    read_head,
    verify_gate_ledger,
)


def _ledger(tmp_path, n=5):
    ledger = GateLedger(tmp_path, gate="g", environment="staging")
    for i in range(n):
        ledger.append({"kind": "call", "tool": f"t{i}", "args": {"i": i}})
    return ledger


def _lines(path):
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _rewrite(path, lines):
    path.write_text("".join(json.dumps(ln, sort_keys=True) + "\n" for ln in lines))


def test_append_stamps_seq_binding_hash_and_head(tmp_path):
    ledger = _ledger(tmp_path, 3)
    lines = _lines(ledger.path)
    assert [ln["seq"] for ln in lines] == [1, 2, 3]
    assert all(ln["binding"] == {"gate": "g", "environment": "staging"} for ln in lines)
    head, problem = read_head(ledger.head_path, ledger.key)
    assert problem is None
    assert (head.entries, head.seq, head.head_hash) == (3, 3, lines[-1]["hash"])


def test_verify_ok_on_clean_ledger(tmp_path):
    ledger = _ledger(tmp_path)
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert ok, problems


def test_ledger_is_keyed_by_default(tmp_path):
    ledger = _ledger(tmp_path, 1)
    assert _lines(ledger.path)[0]["hash"].startswith("hmac-sha256:")
    assert (tmp_path / "ledger.key").exists()


def test_edit_detected_with_line_number(tmp_path):
    ledger = _ledger(tmp_path, 4)
    lines = _lines(ledger.path)
    lines[1]["tool"] = "tampered"
    _rewrite(ledger.path, lines)
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert not ok
    assert any("line 2" in p for p in problems)


def test_middle_deletion_detected(tmp_path):
    ledger = _ledger(tmp_path, 5)
    lines = _lines(ledger.path)
    del lines[2]
    _rewrite(ledger.path, lines)
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert not ok
    assert problems


def test_reorder_detected(tmp_path):
    ledger = _ledger(tmp_path, 4)
    lines = _lines(ledger.path)
    lines[1], lines[2] = lines[2], lines[1]
    _rewrite(ledger.path, lines)
    ok, _problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert not ok


def test_tail_truncation_detected_via_head(tmp_path):
    """The case plain hash chains miss: dropping the tail."""
    ledger = _ledger(tmp_path, 5)
    lines = _lines(ledger.path)
    _rewrite(ledger.path, lines[:3])  # agent deletes the last two lines
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert not ok
    assert any("truncation" in p for p in problems)


def test_forged_head_detected(tmp_path):
    """The attacker also edits the head file to match the truncation."""
    ledger = _ledger(tmp_path, 5)
    lines = _lines(ledger.path)
    _rewrite(ledger.path, lines[:3])
    head = json.loads(ledger.head_path.read_text())
    head["entries"] = 3
    head["seq"] = 3
    ledger.head_path.write_text(json.dumps(head) + "\n")
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert not ok
    assert any("MAC mismatch" in p for p in problems)


def test_appended_past_head_detected(tmp_path):
    ledger = _ledger(tmp_path, 3)
    # Simulate someone appending raw lines without the head commitment.
    with ledger.path.open("a") as fh:
        fh.write(json.dumps({"kind": "call", "tool": "x"}) + "\n")
    ok, problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding=ledger.binding
    )
    assert not ok
    assert any("appended past the head" in p for p in problems)


def test_binding_mismatch_detected(tmp_path):
    ledger = _ledger(tmp_path, 2)
    ok, _problems = verify_gate_ledger(
        ledger.path, ledger.head_path, key=ledger.key, expected_binding={"gate": "other"}
    )
    assert not ok


def test_restart_continues_chain_and_seq(tmp_path):
    _first = _ledger(tmp_path, 3)
    second = GateLedger(tmp_path, gate="g", environment="staging")
    entry = second.append({"kind": "call", "tool": "after-restart"})
    lines = _lines(second.path)
    assert len(lines) == 4
    assert entry["seq"] == 4
    assert entry["prev"] == lines[-2]["hash"]
    ok, problems = verify_gate_ledger(
        second.path, second.head_path, key=second.key, expected_binding=second.binding
    )
    assert ok, problems


def test_events_returns_parsed_entries(tmp_path):
    _ledger(tmp_path, 2)
    again = GateLedger(tmp_path, gate="g", environment="staging")
    events = again.events()
    assert [e["tool"] for e in events] == ["t0", "t1"]
