"""The gate's rule engine: scope, prerequisites, freeze, approval.

A :class:`Policy` is compiled once at startup from a
:class:`~authiro.config.GateConfig`: every tool glob becomes one anchored
regex, so per-call matching is a handful of C-level ``re`` calls.

Two layers of rules apply to every call, in order:

* **Built-in defaults.** ``freeze`` blocks write and destructive calls;
  every destructive call needs a signed human approval. These apply with
  no configuration at all, so an empty policy is already safe.
* **Operator rules.** The YAML ``rules:`` list adds scope checks on
  argument values, prerequisite requirements (a prior successful call
  on matching args, within N seconds), per-rule freeze, and per-rule
  approval requirements.

Refusal shape (what the agent receives, one response, every failing
rule with a fix)::

    {"authiro": "refused", "tool": ..., "risk": ...,
     "reasons": [{"rule": ..., "kind": ..., "message": ..., "fix": ...}],
     "context": {...}}

**Hard vs soft.** Scope violations and freeze are *hard* denies: they
are returned alone, so the agent is not coached toward forbidden calls
("back up prod, then delete it" must never appear as a fix chain).
Prerequisite and approval failures are *soft*: they all appear together
with fixes, because the agent is expected to satisfy them and retry.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from authiro.config import GateConfig, PriorRequirement, Rule
from authiro.risk import DESTRUCTIVE, RISK_ORDER, WRITE

KIND_SCOPE = "scope"
KIND_FREEZE = "freeze"
KIND_PREREQUISITE = "prerequisite"
KIND_APPROVAL = "approval"

_HARD_KINDS = frozenset({KIND_SCOPE, KIND_FREEZE})


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile an fnmatch-style glob into an anchored regex.

    ``*`` matches any run of characters, ``?`` one character; everything
    else is literal. Anchored at both ends so ``cloud_*`` does not match
    ``xcloud_delete``.
    """
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out) + r"\Z")


def _glob_match(pattern: str, value: str) -> bool:
    return glob_to_regex(pattern).match(value) is not None


@dataclass(frozen=True)
class Reason:
    """One failing rule, with the fix that satisfies it.

    ``kind`` is ``scope`` / ``freeze`` (hard) or ``prerequisite`` /
    ``approval`` (soft). ``fix`` is the imperative the agent can act on;
    for hard denies it names the constraint, not a way around it.
    """

    rule: str
    kind: str
    message: str
    fix: str

    def to_dict(self) -> dict[str, Any]:
        """The wire shape of one reason."""
        return {"rule": self.rule, "kind": self.kind, "message": self.message, "fix": self.fix}


@dataclass(frozen=True)
class Decision:
    """The policy verdict for one call.

    ``status`` is ``allowed`` (nothing blocks the call), ``refused``
    (hard deny, or a soft failure the agent must fix first), or
    ``approval_required`` (only the signed approval is missing; the gate
    layer attaches the pending request id).
    """

    status: str
    reasons: tuple[Reason, ...] = ()
    needs_approval: bool = False

    @property
    def allowed(self) -> bool:
        """Whether nothing blocks the call."""
        return self.status == "allowed"


class Policy:
    """Compiled rules plus the built-in safe defaults.

    ``check`` is pure: it takes the freeze flag and an
    ``is_approved(tool, args)`` predicate (supplied by the approvals
    store) and returns a :class:`Decision`. All IO lives one layer up.
    """

    def __init__(self, config: GateConfig) -> None:
        """Compile every rule's tool glob into one anchored regex."""
        self._config = config
        self._rules: list[tuple[re.Pattern[str], Rule]] = [
            (glob_to_regex(rule.when_tool), rule) for rule in config.rules
        ]

    @property
    def config(self) -> GateConfig:
        """The gate configuration this policy was compiled from."""
        return self._config

    # ── Selection ─────────────────────────────────────────────────────────

    def _matching(self, tool: str, risk: str) -> list[Rule]:
        out = []
        for pattern, rule in self._rules:
            if not pattern.match(tool):
                continue
            if rule.when_risk and risk not in rule.when_risk:
                continue
            out.append(rule)
        return out

    # ── Checks ────────────────────────────────────────────────────────────

    @staticmethod
    def _scope_failures(rule: Rule, args: Mapping[str, Any]) -> list[Reason]:
        reasons = []
        for check in rule.scope:
            if check.arg not in args:
                # The rule guards *values* of this argument; a call that
                # does not carry the argument at all is not out of scope
                # (the upstream's own schema rejects a missing required
                # argument). Failing here would refuse every read tool
                # that shares the rule's tool glob.
                continue
            value = args.get(check.arg)
            text = "" if value is None else str(value)
            quoted = f"{check.arg}={text!r}"
            if check.allow and not any(_glob_match(g, text) for g in check.allow):
                reasons.append(
                    Reason(
                        rule=rule.name,
                        kind=KIND_SCOPE,
                        message=rule.message or f"{quoted} is outside the scope this gate permits.",
                        fix=(
                            f"This gate only permits {check.arg} values matching "
                            f"{', '.join(check.allow)}."
                        ),
                    )
                )
            if check.deny and any(_glob_match(g, text) for g in check.deny):
                reasons.append(
                    Reason(
                        rule=rule.name,
                        kind=KIND_SCOPE,
                        message=rule.message or f"{quoted} is denied by scope.",
                        fix=f"Values matching {', '.join(check.deny)} are out of scope here.",
                    )
                )
        return reasons

    @staticmethod
    def _prior_failure(rule: Rule, args: Mapping[str, Any], history: CallHistory) -> Reason | None:
        prior = rule.require_prior
        if prior is None:
            return None
        if history.satisfied(prior, args):
            return None
        fixed = {a: args.get(a) for a in prior.match_args if a in args}
        wanted = {**fixed, **prior.with_args}
        spec = ", ".join(f"{k}={v!r}" for k, v in sorted(wanted.items()))
        return Reason(
            rule=rule.name,
            kind=KIND_PREREQUISITE,
            message=(
                rule.message
                or (
                    f"`{prior.tool}` must succeed first"
                    + (f" with {spec}" if spec else "")
                    + f" within the last {int(prior.within)}s."
                )
            ),
            fix=f"Call `{prior.tool}` with {spec}, then retry."
            if spec
            else f"Call `{prior.tool}`, then retry.",
        )

    def check(
        self,
        tool: str,
        risk: str,
        args: Mapping[str, Any],
        *,
        history: CallHistory,
        freeze: bool,
        is_approved: Callable[[str, Mapping[str, Any]], bool] | None = None,
    ) -> Decision:
        """Evaluate every applicable rule plus the built-in defaults."""
        if risk not in RISK_ORDER:
            raise ValueError(f"unknown risk level {risk!r}")
        rules = self._matching(tool, risk)
        needs_approval = risk == DESTRUCTIVE or any(r.require_approval for r in rules)

        hard: list[Reason] = []
        soft: list[Reason] = []

        for rule in rules:
            hard.extend(self._scope_failures(rule, args))
        for rule in rules:
            prior = self._prior_failure(rule, args, history)
            if prior is not None:
                soft.append(prior)

        freeze_blocks = risk in (WRITE, DESTRUCTIVE) or any(r.deny_if_freeze for r in rules)
        if freeze and freeze_blocks:
            hard.append(
                Reason(
                    rule="freeze",
                    kind=KIND_FREEZE,
                    message="a freeze is active; changes are refused.",
                    fix=(
                        "This gate is frozen: write and destructive calls are refused "
                        "until an operator lifts the freeze (`authiro freeze off`)."
                    ),
                )
            )

        if hard:
            return Decision(status="refused", reasons=tuple(hard), needs_approval=needs_approval)

        if needs_approval and not (is_approved and is_approved(tool, args)):
            soft.append(
                Reason(
                    rule="approval",
                    kind=KIND_APPROVAL,
                    message="this call needs a signed human approval before it can run.",
                    fix=(
                        "A human must sign off on this exact call. The response carries an "
                        "approval id; the human runs `authiro approve <id>` out of band, "
                        "then the call is retried unchanged."
                    ),
                )
            )

        if soft:
            only_approval = all(r.kind == KIND_APPROVAL for r in soft)
            status = "approval_required" if only_approval else "refused"
            return Decision(status=status, reasons=tuple(soft), needs_approval=needs_approval)

        return Decision(status="allowed", needs_approval=needs_approval)


@dataclass
class CallHistory:
    """Bounded in-memory record of successful calls, for prerequisites.

    One deque per tool (default 256 entries), rebuilt from the ledger
    on gate startup so a restart loses nothing. ``satisfied`` answers
    whether a :class:`~authiro.config.PriorRequirement` holds for the
    current call. Wall-clock timestamps (``time.time()``) so entries
    restored from the ledger and fresh entries compare on one axis.
    """

    per_tool_limit: int = 256
    _entries: dict[str, deque[tuple[float, dict[str, Any]]]] = field(default_factory=dict)

    def record(self, tool: str, args: Mapping[str, Any], *, epoch: float | None = None) -> None:
        """Record a successful call (used to satisfy later prerequisites)."""
        q = self._entries.setdefault(tool, deque(maxlen=self.per_tool_limit))
        q.append((epoch if epoch is not None else time.time(), dict(args)))

    def satisfied(self, prior: PriorRequirement, args: Mapping[str, Any]) -> bool:
        """Whether ``prior`` holds for ``args`` right now."""
        deadline = time.time() - prior.within
        for ts, prior_args in reversed(self._entries.get(prior.tool, ())):
            if ts < deadline:
                return False
            if all(prior_args.get(k) == args.get(k) for k in prior.match_args) and all(
                prior_args.get(k) == v for k, v in prior.with_args.items()
            ):
                return True
        return False
