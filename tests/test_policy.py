"""Policy engine: scope, prerequisites, freeze, approval, and the
hard-vs-soft refusal split."""

from __future__ import annotations

import pytest
import yaml

from authiro.config import load_config
from authiro.policy import CallHistory, Policy


def _policy(tmp_path, rules_yaml, **cfg):
    raw = {
        "name": "test-gate",
        "environment": "staging",
        "state_dir": str(tmp_path / "state"),
        "rules": yaml.safe_load(rules_yaml or "[]"),
    }
    raw.update(cfg)
    path = tmp_path / "gate.yaml"
    path.write_text(yaml.dump(raw))
    return Policy(load_config(path))


POCKETOS_RULES = """
- name: staging-session-cannot-touch-prod
  when: {tool: "cloud_*"}
  scope:
    volume_id: {allow: ["stg-*"]}

- name: offsite-backup-before-delete
  when: {tool: cloud_delete_volume}
  require_prior:
    tool: cloud_backup_volume
    match_args: [volume_id]
    with_args: {destination: offsite}
    within: 600
"""


@pytest.fixture()
def history() -> CallHistory:
    return CallHistory()


def test_empty_policy_read_allowed(tmp_path, history):
    p = _policy(tmp_path, "[]")
    d = p.check("cloud_get_status", "read", {}, history=history, freeze=False)
    assert d.status == "allowed"


def test_empty_policy_destructive_needs_approval(tmp_path, history):
    p = _policy(tmp_path, "[]")
    d = p.check("cloud_delete_volume", "destructive", {}, history=history, freeze=False)
    assert d.status == "approval_required"
    assert d.needs_approval


def test_scope_refuses_out_of_scope_argument(tmp_path, history):
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume",
        "destructive",
        {"volume_id": "prod-db"},
        history=history,
        freeze=False,
    )
    assert d.status == "refused"
    scope_reasons = [r for r in d.reasons if r.kind == "scope"]
    assert len(scope_reasons) == 1
    assert "prod-db" in scope_reasons[0].message
    assert scope_reasons[0].fix  # a fix is always present


def test_hard_deny_shown_alone(tmp_path, history):
    """A scope violation must not bundle prerequisite fixes.

    The agent must not be coached from "delete prod-db" toward
    "back up prod-db, then delete it": only the scope reason appears.
    """
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume",
        "destructive",
        {"volume_id": "prod-db"},
        history=history,
        freeze=False,
    )
    assert all(r.kind == "scope" for r in d.reasons)


def test_scope_allows_in_scope_argument(tmp_path, history):
    """In scope, prereq unmet: both soft failures appear with fixes."""
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=False
    )
    assert d.status == "refused"
    kinds = sorted(r.kind for r in d.reasons)
    assert kinds == ["approval", "prerequisite"]  # scope passed; prereq + approval listed


def test_prerequisite_missing(tmp_path, history):
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=False
    )
    assert d.status == "refused"
    prereq = [r for r in d.reasons if r.kind == "prerequisite"]
    assert prereq and "cloud_backup_volume" in prereq[0].message
    assert "offsite" in prereq[0].fix


def test_prerequisite_satisfied_by_matching_prior(tmp_path, history):
    history.record("cloud_backup_volume", {"volume_id": "stg-db", "destination": "offsite"})
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=False
    )
    assert d.status == "approval_required"
    assert all(r.kind != "prerequisite" for r in d.reasons)


def test_on_volume_backup_does_not_satisfy_offsite_requirement(tmp_path, history):
    """The PocketOS lesson: backups on the deleted volume don't count."""
    history.record("cloud_backup_volume", {"volume_id": "stg-db", "destination": "on-volume"})
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=False
    )
    assert d.status == "refused"
    assert any(r.kind == "prerequisite" for r in d.reasons)


def test_prerequisite_expires(tmp_path, history, monkeypatch):
    import time as _time

    p = _policy(tmp_path, POCKETOS_RULES.replace("within: 600", "within: 5"))
    fake_now = [_time.time()]
    monkeypatch.setattr(_time, "time", lambda: fake_now[0])
    history.record("cloud_backup_volume", {"volume_id": "stg-db", "destination": "offsite"})
    fake_now[0] += 10
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=False
    )
    assert any(r.kind == "prerequisite" for r in d.reasons)


def test_prerequisite_needs_same_args(tmp_path, history):
    history.record("cloud_backup_volume", {"volume_id": "other-db", "destination": "offsite"})
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=False
    )
    assert any(r.kind == "prerequisite" for r in d.reasons)


def test_freeze_blocks_write_and_destructive_not_read(tmp_path, history):
    p = _policy(tmp_path, "[]")
    assert p.check("cloud_run_sql", "write", {}, history=history, freeze=True).status == "refused"
    refused = p.check("cloud_delete_volume", "destructive", {}, history=history, freeze=True)
    assert refused.status == "refused"
    assert any(r.kind == "freeze" for r in refused.reasons)
    assert p.check("cloud_get_status", "read", {}, history=history, freeze=True).status == "allowed"


def test_freeze_is_hard_and_shown_alone(tmp_path, history):
    p = _policy(tmp_path, POCKETOS_RULES)
    d = p.check(
        "cloud_delete_volume", "destructive", {"volume_id": "stg-db"}, history=history, freeze=True
    )
    assert [r.kind for r in d.reasons] == ["freeze"]


def test_rule_freeze_via_deny_if_freeze(tmp_path, history):
    rules = """
- name: freeze-reads-too
  when: {tool: cloud_get_*}
  deny_if_freeze: true
"""
    p = _policy(tmp_path, rules)
    d = p.check("cloud_get_status", "read", {}, history=history, freeze=True)
    assert d.status == "refused"
    assert any(r.kind == "freeze" for r in d.reasons)


def test_require_approval_rule_for_non_destructive(tmp_path, history):
    rules = """
- name: outbound-needs-signoff
  when: {tool: slack_post_message}
  require_approval: true
"""
    p = _policy(tmp_path, rules)
    d = p.check("slack_post_message", "write", {"channel": "#x"}, history=history, freeze=False)
    assert d.status == "approval_required"


def test_all_soft_failures_listed_together(tmp_path, history):
    """R8: one response lists every failing rule with a fix."""
    rules = """
- name: first-prereq
  when: {tool: deploy_all}
  require_prior: {tool: run_tests, within: 300}
- name: second-prereq
  when: {tool: deploy_all}
  require_prior: {tool: build, within: 300}
- name: deploy-needs-approval
  when: {tool: deploy_all}
  require_approval: true
"""
    p = _policy(tmp_path, rules)
    d = p.check("deploy_all", "write", {}, history=history, freeze=False)
    kinds = sorted(r.kind for r in d.reasons)
    assert kinds == ["approval", "prerequisite", "prerequisite"]
    assert all(r.fix for r in d.reasons)


def test_config_env_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "abc123")
    cfg = tmp_path / "gate.yaml"
    cfg.write_text(
        """
name: env-gate
upstreams:
  cloud:
    command: python
    args: [server.py]
    env: {TOKEN: "${SECRET_TOKEN}", MISSING: "${NOPE_XYZ}"}
"""
    )
    from authiro.config import load_config

    config = load_config(cfg)
    assert config.upstreams["cloud"]["env"]["TOKEN"] == "abc123"
    assert config.upstreams["cloud"]["env"]["MISSING"] == ""


def test_config_rejects_missing_file(tmp_path):
    from authiro.config import load_config

    with pytest.raises(ValueError, match="not found"):
        load_config(tmp_path / "nope.yaml")
