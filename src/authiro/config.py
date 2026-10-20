"""Gate configuration: one YAML file per gate.

The file names the gate, pins the environment the session may touch,
points at the upstream MCP servers (whose credentials live in the gate
process, never in the agent's), and carries the risk overrides and rules
the policy layer compiles.

Minimal example (the full PocketOS policy lives in ``demos/pocketos``)::

    name: pocketos-gate
    environment: staging
    state_dir: .authiro
    approver_public_key: approver.pub
    approval_ttl: 900

    upstreams:
      cloud:
        command: python
        args: [cloud_server.py]
        env: {RAILWAY_TOKEN: "${RAILWAY_TOKEN}"}

    risk_overrides:
      "cloud_backup_*": write

    rules:
      - name: offsite-backup-before-delete
        when: {tool: cloud_delete_volume}
        require_prior:
          tool: cloud_backup_volume
          match_args: [volume_id]
          with_args: {destination: offsite}
          within: 600

Environment-variable values in ``${VAR}`` form are expanded from the
gate's own environment at load time, so an upstream credential never has
to be written into the YAML.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from authiro.risk import DESTRUCTIVE, READ, WRITE

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

#: Default seconds an approval stays valid after the human signs it.
DEFAULT_APPROVAL_TTL = 900


def _expand_env(value: str) -> str:
    """Expand ``${VAR}`` references from the gate process environment.

    An unset variable expands to the empty string, matching how the
    upstream config would behave if the operator left the value blank;
    the upstream then fails its own auth and the gate logs it, instead
    of the gate refusing to start on a missing optional secret.
    """

    def sub(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), "")

    return _ENV_REF.sub(sub, value)


def _expand_tree(value: Any) -> Any:
    if isinstance(value, str):
        return _expand_env(value)
    if isinstance(value, dict):
        return {k: _expand_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_tree(v) for v in value]
    return value


@dataclass(frozen=True)
class PriorRequirement:
    """``require_prior``: a tool that must have succeeded first.

    ``tool`` must have completed successfully within ``within`` seconds,
    with the same values as the current call for every arg named in
    ``match_args`` and the exact values in ``with_args``. An on-volume
    backup does not satisfy an offsite requirement because
    ``with_args`` pins ``destination: offsite``.
    """

    tool: str
    match_args: tuple[str, ...] = ()
    with_args: dict[str, Any] = field(default_factory=dict)
    within: float = 600


@dataclass(frozen=True)
class ScopeCheck:
    """``scope`` for one argument: allow/deny glob lists on its value."""

    arg: str
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    """One gate rule, compiled from YAML.

    ``when_tool`` / ``when_risk`` select the calls the rule applies to
    (globs over the proxy tool name; a risk list). The body is any of
    ``scope`` checks, a ``require_prior``, ``deny_if_freeze``, and
    ``require_approval``. ``message`` replaces the generated refusal
    text for this rule.
    """

    name: str
    when_tool: str = "*"
    when_risk: tuple[str, ...] = (READ, WRITE, DESTRUCTIVE)
    scope: tuple[ScopeCheck, ...] = ()
    require_prior: PriorRequirement | None = None
    deny_if_freeze: bool = False
    require_approval: bool = False
    message: str = ""


@dataclass(frozen=True)
class GateConfig:
    """Everything the gate needs at startup, from one YAML file.

    ``upstreams`` maps a server name to a fastmcp client transport
    config: ``{command, args, env, cwd}`` for stdio or ``{url}`` for a
    remote server. ``environment`` is the ground truth the gate reports
    in ``authiro://context`` and stamps into refusals and approvals.
    """

    name: str
    environment: str = "default"
    state_dir: str | Path = ".authiro"
    approver_public_key: str | Path | None = None
    approval_ttl: int = DEFAULT_APPROVAL_TTL
    upstreams: dict[str, Any] = field(default_factory=dict)
    risk_overrides: dict[str, str] = field(default_factory=dict)
    rules: tuple[Rule, ...] = ()
    freeze: bool = False

    def resolved_state_dir(self) -> Path:
        """The state directory (ledger, head, approvals db) as a Path."""
        return Path(self.state_dir)


def _parse_rule(name: str, body: Mapping[str, Any]) -> Rule:
    when = dict(body.get("when") or {})
    scope_body = dict(body.get("scope") or {})
    scope = tuple(
        ScopeCheck(
            arg=arg,
            allow=tuple(str(g) for g in dict(spec or {}).get("allow", [])),
            deny=tuple(str(g) for g in dict(spec or {}).get("deny", [])),
        )
        for arg, spec in scope_body.items()
    )
    prior_body = dict(body.get("require_prior") or {})
    prior = None
    if prior_body:
        prior = PriorRequirement(
            tool=str(prior_body["tool"]),
            match_args=tuple(str(a) for a in prior_body.get("match_args", [])),
            with_args=_expand_tree(dict(prior_body.get("with_args") or {})),
            within=float(prior_body.get("within", 600)),
        )
    when_risk = tuple(str(r) for r in when.get("risk", ())) or (READ, WRITE, DESTRUCTIVE)
    return Rule(
        name=name,
        when_tool=str(when.get("tool", "*")),
        when_risk=when_risk,
        scope=scope,
        require_prior=prior,
        deny_if_freeze=bool(body.get("deny_if_freeze", False)),
        require_approval=bool(body.get("require_approval", False)),
        message=str(body.get("message", "")),
    )


def load_config(path: str | Path) -> GateConfig:
    """Load and validate a gate YAML file.

    Raises ``ValueError`` with the offending key on a malformed file so
    a typo fails at startup, not at the first destructive call.
    """
    import yaml

    p = Path(path)
    if not p.exists():
        raise ValueError(f"gate config not found: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"gate config must be a YAML mapping; got {type(raw).__name__}")
    if "upstreams" in raw and not isinstance(raw["upstreams"], dict):
        raise ValueError("gate config 'upstreams' must be a mapping of server name to config")

    rules = tuple(
        _parse_rule(str(body.get("name", f"rule-{i}")), dict(body))
        for i, body in enumerate(raw.get("rules") or [])
    )
    overrides = {str(k): str(v) for k, v in dict(raw.get("risk_overrides") or {}).items()}
    upstreams = {
        str(name): _expand_tree(dict(cfg)) for name, cfg in dict(raw.get("upstreams") or {}).items()
    }
    key = raw.get("approver_public_key")
    return GateConfig(
        name=str(raw.get("name", p.stem)),
        environment=str(raw.get("environment", "default")),
        state_dir=raw.get("state_dir", ".authiro"),
        approver_public_key=str(key) if key is not None else None,
        approval_ttl=int(raw.get("approval_ttl", DEFAULT_APPROVAL_TTL)),
        upstreams=upstreams,
        risk_overrides=overrides,
        rules=rules,
        freeze=bool(raw.get("freeze", False)),
    )
