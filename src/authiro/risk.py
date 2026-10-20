"""Tool risk classification: read, write, destructive.

Every tool call that reaches the gate is classified before any rule
runs. The classifier answers two questions:

* **Static risk** — what does this tool *do*? Resolved once per tool
  name from (in precedence order) operator override, the upstream's
  MCP annotations, a verb found in the tool name, and — failing all
  of those — ``destructive`` (fail closed; an unread tool is a dangerous
  tool).
* **Argument escalation** — what does this *call* ask for? The argument
  values are scanned for destructive SQL (``DROP TABLE``, ``TRUNCATE``,
  ``DELETE FROM``) and shell (``rm -rf``) payloads. Escalation can raise
  a call to ``destructive``; it can never lower it, so a read-marked
  ``run_sql("DROP TABLE users")`` is still destructive.

``classify`` returns a :class:`RiskResult` carrying the risk level, the
source that decided it, and a human-readable detail line. ``authiro
check`` prints one such line per tool.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

READ = "read"
WRITE = "write"
DESTRUCTIVE = "destructive"

RISK_ORDER = {READ: 0, WRITE: 1, DESTRUCTIVE: 2}
_VALID_RISKS = frozenset(RISK_ORDER)

# Verb stems matched against the tool name. The longest stem wins, so
# "reboot" is not read as "delete"-adjacent; matching is on word-ish
# boundaries after splitting on "_" (proxy names like
# "cloud_delete_volume" split into the upstream's own words).
_DESTRUCTIVE_VERBS = (
    "delete",
    "del",
    "drop",
    "remove",
    "destroy",
    "truncate",
    "wipe",
    "purge",
    "erase",
    "format",
    "kill",
    "terminate",
    "shutdown",
    "reset",
)
_WRITE_VERBS = (
    "write",
    "create",
    "insert",
    "update",
    "set",
    "put",
    "post",
    "add",
    "append",
    "patch",
    "modify",
    "push",
    "deploy",
    "apply",
    "commit",
    "upload",
    "send",
    "publish",
    "post_message",
    "start",
    "stop",
    "restart",
    "reboot",
    "backup",
    "restore",
    "grant",
    "revoke",
    "run",
    "execute",
    "invoke",
    "call",
    "approve",
    "deny",
    "cancel",
    "close",
    "open",
    "connect",
    "disconnect",
    "init",
    "install",
    "sign",
    "mint",
    "burn",
    "transfer",
)
_READ_VERBS = (
    "get",
    "list",
    "read",
    "fetch",
    "query",
    "search",
    "find",
    "describe",
    "show",
    "view",
    "inspect",
    "check",
    "verify",
    "validate",
    "health",
    "status",
    "count",
    "exists",
    "stat",
    "head",
    "lookup",
    "scan",
    "select",
    "echo",
    "ping",
)

# Argument-escalation patterns. Each is a case-insensitive regex applied
# to every stringified argument value of the call. A match escalates the
# call to destructive regardless of the tool's static risk.
_DEFAULT_ESCALATION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|ROLE|USER)\b",
        r"\bTRUNCATE\s+(TABLE\b)?",
        r"\bDELETE\s+FROM\b",
        r"\bALTER\s+TABLE\b.*\bDROP\b",
        r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b",
        r"\bmkfs(\.\w+)?\b",
        r"\bdd\s+if=",
        r"\bshutdown\b",
        r"\breboot\b",
    )
)

_MAX_SCAN_DEPTH = 6
_MAX_SCAN_STRING = 100_000


def _compile_globs(
    patterns: Mapping[str, str] | Mapping[str, Any],
) -> list[tuple[re.Pattern[str], str]]:
    """Compile ``{glob: risk}`` overrides into ``(regex, risk)`` pairs.

    The glob dialect is fnmatch-style (``*`` matches anything), anchored
    at both ends so ``cloud_delete_*`` matches ``cloud_delete_volume``
    but not ``xcloud_delete_volume``.
    """
    compiled = []
    for pattern, risk in patterns.items():
        if risk not in _VALID_RISKS:
            raise ValueError(
                f"risk override for {pattern!r} must be one of {sorted(_VALID_RISKS)}; got {risk!r}"
            )
        compiled.append((re.compile(re.escape(pattern).replace(r"\*", ".*") + r"\Z"), str(risk)))
    return compiled


@dataclass(frozen=True)
class RiskResult:
    """The classification of one tool (or one call, after escalation).

    ``risk`` is one of ``read`` / ``write`` / ``destructive``. ``source``
    names what decided it — ``override``, ``annotation``, ``verb``, or
    ``default`` — and, for a per-call result, ``escalation`` when the
    arguments raised it. ``detail`` is the single line ``authiro check``
    prints.
    """

    risk: str
    source: str
    detail: str = ""


class RiskClassifier:
    """Classify tools by override, annotation, verb, then default.

    ``overrides`` is a ``{glob: risk}`` map from the gate's YAML; it wins
    over everything. ``annotations`` come from the upstream's
    ``tools/list`` (``readOnlyHint`` → read, ``destructiveHint`` →
    destructive). The verb pass matches the tool name's segments against
    the verb stems above; the strongest verb found decides. Tools with no
    signal at all are ``destructive`` — fail closed.
    """

    def __init__(
        self,
        overrides: Mapping[str, str] | None = None,
        *,
        escalation_patterns: tuple[re.Pattern[str], ...] | None = None,
    ) -> None:
        """Store compiled overrides and escalation patterns."""
        self._overrides = _compile_globs(overrides or {})
        self._escalations = escalation_patterns or _DEFAULT_ESCALATION_PATTERNS

    def classify(
        self,
        tool: str,
        *,
        annotations: Mapping[str, Any] | None = None,
        name_for_verbs: str | None = None,
    ) -> RiskResult:
        """Resolve a tool's static risk. Call once per tool; cache it.

        ``tool`` is the proxy-visible name (what operator overrides in
        the YAML glob against, e.g. ``cloud_backup_*``);
        ``name_for_verbs`` is the upstream's own tool name, whose words
        carry the verb signal (``delete_volume``, not
        ``cloud_delete_volume`` — though both classify the same unless
        the server name is itself a verb).
        """
        for pattern, risk in self._overrides:
            if pattern.match(tool):
                return RiskResult(risk, "override", f"operator override → {risk}")
        ann = dict(annotations or {})
        if ann.get("destructiveHint"):
            return RiskResult(DESTRUCTIVE, "annotation", "upstream annotation destructiveHint")
        if ann.get("readOnlyHint"):
            return RiskResult(READ, "annotation", "upstream annotation readOnlyHint")
        verb_risk, verb = self._verb_risk(name_for_verbs if name_for_verbs is not None else tool)
        if verb_risk is not None:
            return RiskResult(verb_risk, "verb", f"verb {verb!r} in name → {verb_risk}")
        return RiskResult(
            DESTRUCTIVE, "default", "no override, annotation, or verb matched → fail closed"
        )

    @staticmethod
    def _verb_risk(tool: str) -> tuple[str | None, str | None]:
        """Find the strongest verb stem inside the tool name, if any."""
        segments = re.split(r"[^a-z0-9]+", tool.lower())
        best: tuple[int, str] | None = None
        for seg in segments:
            if seg in _DESTRUCTIVE_VERBS:
                rank = (2, seg)
            elif seg in _WRITE_VERBS:
                rank = (1, seg)
            elif seg in _READ_VERBS:
                rank = (0, seg)
            else:
                continue
            if best is None or rank[0] > best[0]:
                best = rank
        if best is None:
            return None, None
        return (READ, WRITE, DESTRUCTIVE)[best[0]], best[1]

    def escalate(self, args: Mapping[str, Any], static: RiskResult) -> RiskResult:
        """Return the call's risk after scanning ``args`` for payloads.

        Escalation only ever raises: a ``read`` tool called with
        ``DROP TABLE`` SQL classifies destructive. A ``destructive``
        static risk is never lowered by clean arguments.
        """
        if static.risk == DESTRUCTIVE:
            return static
        hit = self._first_match(args, depth=0)
        if hit is None:
            return static
        return RiskResult(
            DESTRUCTIVE,
            "escalation",
            f"argument escalation ({hit}) raised {static.risk} → destructive",
        )

    def _first_match(self, value: Any, *, depth: int) -> str | None:
        """Depth-limited scan of an argument value for escalation patterns."""
        if depth > _MAX_SCAN_DEPTH:
            return None
        if isinstance(value, str):
            return self._string_match(value)
        if isinstance(value, Mapping):
            return self._first_child(value.values(), depth=depth)
        if isinstance(value, (list, tuple)):
            return self._first_child(value, depth=depth)
        return None

    def _string_match(self, value: str) -> str | None:
        """Whether a string argument matches any escalation pattern."""
        if not value or len(value) > _MAX_SCAN_STRING:
            return None
        for pattern in self._escalations:
            if pattern.search(value):
                return pattern.pattern
        return None

    def _first_child(self, values: Any, *, depth: int) -> str | None:
        """Scan a container's children (one level deeper)."""
        for v in values:
            hit = self._first_match(v, depth=depth + 1)
            if hit is not None:
                return hit
        return None


def args_hash(args: Mapping[str, Any]) -> str:
    """A stable hash of a call's arguments; approvals bind to it.

    Canonical JSON (sorted keys) under sha256, so an approval granted
    for ``volume_id='stg-db'`` cannot be replayed against
    ``volume_id='prod-db'``.
    """
    import hashlib
    import json

    payload = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
