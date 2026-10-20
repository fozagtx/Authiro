"""The PocketOS replay runs end to end with no API key or model.

Covers the PRD's demo beats as one scripted flow: the raw run destroys
the database, the gated run survives every move, the receipt tells the
truth, and the tamper check names the broken line.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "demos" / "pocketos" / "replay.py"


def _load_replay():
    spec = importlib.util.spec_from_file_location("pocketos_replay", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["pocketos_replay"] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_pocketos_replay_end_to_end(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)  # demo writes nothing into the repo
    replay = _load_replay()
    state_dir, _store, _signer = await replay.run_gated_agent(tmp_path)
    out = capsys.readouterr().out
    assert "prod-db" in out
    assert "outside the scope" in out
    assert "signature" in out
    assert "executed" in out

    ledger_events = state_dir / "ledger.jsonl"
    assert ledger_events.exists()
    raw = ledger_events.read_text()
    assert "approval_forged" in raw

    # The receipt and tamper check run through the real CLI code path.
    replay.show_receipt_and_tamper(state_dir, tmp_path / "authiro.yaml")
    out2 = capsys.readouterr().out
    assert "tampering detected" in out2
