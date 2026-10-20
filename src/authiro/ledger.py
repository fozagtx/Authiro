"""Hash-chained audit ledger.

Every recorded attempt (a step or a refusal) is appended as one JSONL line
carrying ``prev`` (the previous line's hash) and ``hash`` (sha256 or
HMAC-sha256 over the previous hash plus this entry's canonical encoding).
Editing, reordering, or inserting any earlier line breaks every later hash,
so ``verify_ledger`` points at the exact line where the chain diverges.

What the chain proves and does not prove:

* **Proves**: in-place edits, reorderings, duplications, and middle-deletions
  of recorded entries (with the exact offending line called out).
* **Does not prove on its own**:
  - *Truncation* (dropping the tail-most entry leaves a chain that still
    self-verifies). Detect by external commitment of expected-length, or by
    streaming each entry to append-only storage as it is written.
  - *Whole-cloth forgery* under the default (unkeyed) mode. The hash
    function is public, so a holder of write access to ``ledger.jsonl`` can
    mint a chain from scratch. Set ``AUTHIRO_LEDGER_KEY`` (hex-encoded
    bytes) in the server's environment to switch the chain to HMAC; forgery
    then requires the key.
  - *Cross-session replay* unless the entries carry their ``app_id`` and
    ``project`` in the hashed payload. ``mount()`` binds both by default, so
    copying a ``ledger.jsonl`` from session A into session B's directory
    fails ``verify`` because the binding does not match the on-disk path.
  - *Origin*: a signature over the head would add non-repudiation; the chain
    alone does not.
  - *Existence of any particular session*: deleting a whole session
    directory is invisible to ``verify``; detect by external manifest.

For regulated audit trails, layer external commitments (RFC 3161 timestamp
authority, transparency log, append-only object storage with retention
locks) on top.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "sha256:" + "0" * 64
GENESIS_HMAC = "hmac-sha256:" + "0" * 64

#: Filenames of the proxy-mode gate ledger surfaces inside ``state_dir``.
LEDGER_FILENAME = "ledger.jsonl"
HEAD_FILENAME = "ledger.head"
KEY_FILENAME = "ledger.key"

_LOG = logging.getLogger("authiro")


def _canonical(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def _resolve_key(explicit: bytes | None) -> bytes | None:
    """Return the HMAC key from ``explicit`` or ``AUTHIRO_LEDGER_KEY``.

    The env var must be hex-encoded; a non-hex value raises ``ValueError``
    so a typo cannot silently produce a different chain than the operator
    intended. ``None`` means plain SHA256.
    """
    if explicit is not None:
        return explicit
    env = os.environ.get("AUTHIRO_LEDGER_KEY")
    if not env:
        return None
    try:
        return bytes.fromhex(env)
    except ValueError as exc:
        raise ValueError(
            "AUTHIRO_LEDGER_KEY must be hex-encoded bytes (e.g. the output "
            "of `openssl rand -hex 32`). Got a value that is not valid hex."
        ) from exc


def _digest(prev: str, entry_without_hash: dict[str, Any], key: bytes | None) -> str:
    payload = (prev + _canonical(entry_without_hash)).encode()
    if key is None:
        return "sha256:" + hashlib.sha256(payload).hexdigest()
    return "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()


class HashChainedLedger:
    """Append-only JSONL chain. One instance per ``ledger.jsonl`` file.

    ``binding`` is an optional dict of session identity fields (``app_id``,
    ``project``, ``partition_key``) that lands inside every entry's hashed
    payload. The adapter binds these by default so a ledger cannot be moved
    to a different session directory and still verify.

    ``key`` is an optional HMAC key. ``None`` (the default) uses plain
    SHA256; pass bytes (or set ``AUTHIRO_LEDGER_KEY`` in the env as a hex
    string) to switch to HMAC-SHA256, which makes forgery require the key.

    **Stability**: the on-disk format (canonical JSON, ``prev`` / ``hash`` /
    ``binding`` field names, genesis string) is stable for the v0.x series
    but considered provisional. A future major release may add a
    ``schema_version`` field and version-gated verification; older ledger
    files will continue to verify under their original schema. Do not
    serialize the ``HashChainedLedger`` class itself; treat the JSONL file
    as the contract.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        binding: dict[str, Any] | None = None,
        key: bytes | None = None,
        last_hash: str | None = None,
    ) -> None:
        """Bind the ledger to ``path``; see the class docstring for kwargs."""
        self.path = Path(path)
        self.binding = dict(binding or {})
        self.key = _resolve_key(key)
        # Optional caller-supplied last hash; lets a single-process repeat
        # appender skip the O(n) file re-read between writes. Caller is
        # responsible for keeping the cache consistent. Leave ``None`` to
        # always read from disk.
        self._cached_last_hash: str | None = last_hash

    def _genesis(self) -> str:
        return GENESIS_HMAC if self.key is not None else GENESIS

    def _last_hash(self) -> str:
        if self._cached_last_hash is not None:
            return self._cached_last_hash
        if not self.path.exists():
            return self._genesis()
        last = self._genesis()
        with self.path.open(encoding="utf-8") as fh:  # pragma: no mutate
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line).get("hash", last)
        return last

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Chain ``event`` onto the ledger and return the written entry.

        The entry is the event plus its ``prev``, ``binding``, and ``hash``.
        """
        prev = self._last_hash()
        entry = event | {"prev": prev}
        if self.binding:
            entry["binding"] = self.binding
        entry["hash"] = _digest(prev, entry, self.key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:  # pragma: no mutate
            fh.write(_canonical(entry) + "\n")
        # Keep cache consistent for the next append on this instance.
        self._cached_last_hash = entry["hash"]
        return entry


def verify_ledger(
    path: str | Path,
    *,
    expected_binding: dict[str, Any] | None = None,
    key: bytes | None = None,
    expected_min_entries: int | None = None,
) -> tuple[bool, list[str]]:
    """Recompute the chain. Returns ``(ok, problems)``.

    Each problem names the line where the recorded hash, the prev-link, the
    binding, an entry-count expectation, or JSON decoding fails. A missing
    file is vacuously valid.

    ``expected_binding`` (typically ``{"app_id": ..., "project": ...}``)
    refuses entries whose stored binding does not match; this is what makes
    cross-session replay (copying ledger.jsonl to a different app dir)
    detectable.

    ``key`` (or ``AUTHIRO_LEDGER_KEY`` env) verifies an HMAC-keyed chain;
    pass ``None`` for the default unkeyed chain.

    ``expected_min_entries`` refuses a ledger shorter than the given count;
    use it with an external claim of recorded length to detect truncation.

    Line numbers in problems are 1-based file lines. When the ledger's
    stored hash prefix and the provided key disagree on keyed-vs-unkeyed
    mode, the single problem returned names the key mismatch instead of
    flagging every entry as altered.
    """
    p = Path(path)
    if not p.exists():
        return True, []
    resolved_key = _resolve_key(key)
    stored_mode = _stored_mode(p)
    if stored_mode == "keyed" and resolved_key is None:
        return False, [
            "keyed ledger (hmac-sha256 entries) verified without a key; set "
            "AUTHIRO_LEDGER_KEY to the key this ledger was written with"
        ]
    if stored_mode == "unkeyed" and resolved_key is not None:
        return False, [
            "unkeyed ledger (sha256 entries) verified with a key; unset "
            "AUTHIRO_LEDGER_KEY, or treat this as tampering if the ledger "
            "was expected to be keyed"
        ]
    problems, count, hash_mismatches = _walk_chain(p, expected_binding, resolved_key)
    if resolved_key is not None and count > 0 and hash_mismatches == count:
        problems.append(
            "every entry fails under the provided key; AUTHIRO_LEDGER_KEY "
            "likely does not match the key this ledger was written with"
        )
    if expected_min_entries is not None and count < expected_min_entries:
        problems.append(
            f"truncation: ledger has {count} entries; expected at least {expected_min_entries}"
        )
    return (not problems), problems


def _walk_chain(
    p: Path,
    expected_binding: dict[str, Any] | None,
    resolved_key: bytes | None,
) -> tuple[list[str], int, int]:
    """Recompute the chain line by line: ``(problems, entries, hash_mismatches)``."""
    problems: list[str] = []
    prev = GENESIS_HMAC if resolved_key is not None else GENESIS
    count = 0
    hash_mismatches = 0
    prev_seq: int | None = None
    with p.open(encoding="utf-8") as fh:  # pragma: no mutate
        for i, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                # A verifier must report corruption, not crash on it. The
                # garbled line is flagged here; the next valid entry's
                # prev-link check flags the break in the chain itself.
                problems.append(f"line {i}: not valid JSON ({exc.msg})")
                continue
            entry_problems = _check_entry(i, entry, prev, expected_binding, resolved_key)
            hash_mismatches += sum("hash mismatch" in msg for msg in entry_problems)
            problems.extend(entry_problems)
            problems.extend(_seq_gap_problem(i, entry.get("seq"), prev_seq))
            if isinstance(entry.get("seq"), int):
                prev_seq = entry["seq"]
            prev = entry.get("hash")
            count += 1
    return problems, count, hash_mismatches


def _seq_gap_problem(i: int, seq: Any, prev_seq: int | None) -> list[str]:
    """Name a jump in the monotone seq numbering (a deleted entry) at line ``i``."""
    if isinstance(seq, int) and isinstance(prev_seq, int) and seq > prev_seq + 1:
        return [f"line {i}: seq gap ({prev_seq} -> {seq}); {seq - prev_seq - 1} entry(ies) missing"]
    return []


def _stored_mode(p: Path) -> str | None:
    """Sniff whether the on-disk chain is keyed, from the first entry's hash prefix."""
    with p.open(encoding="utf-8") as fh:  # pragma: no mutate
        for line in fh:
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError):
                h = json.loads(line).get("hash") or ""
                if h.startswith("hmac-sha256:"):
                    return "keyed"
                if h.startswith("sha256:"):
                    return "unkeyed"
            return None
    return None


def attestation_receipt(path: str | Path, *, key: bytes | None = None) -> dict[str, Any]:
    """A portable, machine-readable proof of a ledger's chain head.

    Returns ``{ok, entries, head_hash, keyed, problems}``. Store the receipt
    next to an external audit record; re-running verification later and
    checking ``head_hash`` still matches proves no entry was added, removed,
    or altered since. A missing ledger is vacuously valid (``None`` head,
    zero entries).
    """
    p = Path(path)
    ok, problems = verify_ledger(p, key=key)
    head: str | None = None
    entries = 0
    if p.exists():
        with p.open(encoding="utf-8") as fh:  # pragma: no mutate
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entries += 1
                with contextlib.suppress(json.JSONDecodeError):
                    head = json.loads(line).get("hash", head)
    return {
        "ok": ok,
        "entries": entries,
        "head_hash": head,
        "keyed": _resolve_key(key) is not None,
        "problems": problems,
    }


def _check_entry(
    i: int,
    entry: dict[str, Any],
    prev: str,
    expected_binding: dict[str, Any] | None,
    resolved_key: bytes | None,
) -> list[str]:
    """Per-entry checks: hash, prev-link, and binding match."""
    problems: list[str] = []
    payload = {k: v for k, v in entry.items() if k != "hash"}
    recomputed = _digest(prev, payload, resolved_key)
    if entry.get("prev") != prev:
        problems.append(f"line {i}: prev-link mismatch (chain broken before here)")
    if entry.get("hash") != recomputed:
        problems.append(f"line {i}: hash mismatch (entry was altered)")
    if expected_binding is not None:
        got = entry.get("binding") or {}
        missing = [k for k, v in expected_binding.items() if got.get(k) != v]
        if missing:
            problems.append(
                f"line {i}: binding mismatch on {missing} (ledger does not belong to this session)"
            )
    return problems


def ledger_count(path: str | Path) -> int:
    """Return the number of non-empty lines in ``path``. 0 if missing."""
    p = Path(path)
    if not p.exists():
        return 0
    with p.open(encoding="utf-8") as fh:  # pragma: no mutate
        return sum(1 for line in fh if line.strip())


# ── Gate ledger: keyed chain + MAC'd head file ─────────────────────────────
#
# The proxy-mode gate layers three tamper-evidence surfaces on the chain:
#
# * the chain itself (edits, reorders, middle-deletions),
# * a ``seq`` counter stamped into every entry (monotone; gaps name
#   deleted entries even without the head file),
# * a head file recording ``(entries, head_hash, seq)`` under an HMAC,
#   so tail truncation — dropping the last lines, which leaves a chain
#   that still self-verifies — is caught by comparing the shrunken
#   ledger against the committed head.


@dataclass(frozen=True)
class HeadRecord:
    """The committed state of a gate ledger's chain head.

    ``entries`` is the number of ledger lines committed, ``head_hash``
    the hash of the last one, ``seq`` the last entry's sequence number.
    The head file stores this record plus an HMAC over it; an attacker
    who truncates the ledger cannot shrink the head to match without
    the key.
    """

    entries: int
    head_hash: str
    seq: int


def _head_mac(record: HeadRecord, key: bytes) -> str:
    payload = f"{record.entries}:{record.head_hash}:{record.seq}".encode()
    return "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()


def write_head(path: str | Path, record: HeadRecord, key: bytes) -> None:
    """Atomically commit the chain head (tmp file + rename)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "entries": record.entries,
        "head_hash": record.head_hash,
        "seq": record.seq,
        "mac": _head_mac(record, key),
    }
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(_canonical(body) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def read_head(path: str | Path, key: bytes) -> tuple[HeadRecord | None, str | None]:
    """Read and MAC-check the head file.

    Returns ``(record, problem)``: a missing file is ``(None, None)``
    (no commitment made yet); a present-but-corrupt or MAC-mismatching
    file is ``(None, problem)`` — a MAC mismatch means the head file
    itself was edited without the key.
    """
    p = Path(path)
    if not p.exists():
        return None, None
    try:
        body = json.loads(p.read_text(encoding="utf-8"))
        record = HeadRecord(
            entries=int(body["entries"]),
            head_hash=str(body["head_hash"]),
            seq=int(body["seq"]),
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None, f"head file {p.name} is corrupt (not a valid head record)"
    expected = _head_mac(record, key)
    if body.get("mac") != expected:
        return None, f"head file {p.name} MAC mismatch (head file was altered without the key)"
    return record, None


def scan_ledger_stats(path: str | Path) -> tuple[int, str | None, int | None]:
    """Cheap tail scan: ``(entries, head_hash, last_seq)`` of a ledger file.

    O(1) for the hash and seq (reads the last non-empty line only) plus
    one line count; used by the gate on startup and by verification to
    compare the ledger against the committed head.
    """
    p = Path(path)
    if not p.exists():
        return 0, None, None
    entries = 0
    last: dict[str, Any] | None = None
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entries += 1
            last = None
            with contextlib.suppress(json.JSONDecodeError):
                last = json.loads(line)
    return entries, (last or {}).get("hash"), (last or {}).get("seq")


def resolve_gate_key(state_dir: str | Path, explicit: bytes | None = None) -> bytes:
    """Resolve the gate's HMAC key: explicit > env > persisted file.

    The gate runs keyed by default: with no ``AUTHIRO_LEDGER_KEY`` and
    no persisted key, a fresh 32-byte key is generated into
    ``state_dir/ledger.key`` (mode 0600) and reused from then on. That
    file is the weak spot an attacker with the machine can read; the
    trust model says run the gate as a separate OS user and supply
    ``AUTHIRO_LEDGER_KEY`` from a secrets manager for real deployments.
    """
    if explicit is not None:
        return explicit
    env = _resolve_key(None)
    if env is not None:
        return env
    key_path = Path(state_dir) / KEY_FILENAME
    if key_path.exists():
        raw = key_path.read_bytes().strip()
        if raw:
            return bytes.fromhex(raw.decode())
    key = secrets.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(key.hex() + "\n", encoding="utf-8")
    key_path.chmod(0o600)
    return key


def _fsync() -> bool:
    """Whether ledger appends fsync (``AUTHIRO_LEDGER_FSYNC``)."""
    return bool(os.environ.get("AUTHIRO_LEDGER_FSYNC"))


def _last_line(path: Path) -> dict[str, Any] | None:
    """Read only the last non-empty JSON line of a ledger file."""
    if not path.exists():
        return None
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        window = min(size, 65_536)
        fh.seek(max(0, size - window))
        tail = fh.read(window).decode("utf-8", "replace")
    for line in reversed([ln for ln in tail.splitlines() if ln.strip()]):
        with contextlib.suppress(json.JSONDecodeError):
            entry: dict[str, Any] = json.loads(line)
            return entry
    return None


class GateLedger:
    """The proxy-mode ledger: keyed chain + head file, cross-process safe.

    One instance per gate. Every recorded decision (call, result,
    refusal, approval event) is one JSONL line carrying a monotone
    ``seq``; after each append the head file is recommitted under an
    HMAC. The gate process and the ``authiro approve`` CLI both append
    through this class; a file lock serializes the read-tail/append/
    recommit sequence across processes.
    """

    def __init__(
        self,
        state_dir: str | Path,
        *,
        gate: str,
        environment: str,
        key: bytes | None = None,
    ) -> None:
        """Bind to ``state_dir``; see the class docstring for kwargs."""
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / LEDGER_FILENAME
        self.head_path = self.state_dir / HEAD_FILENAME
        self.gate = gate
        self.environment = environment
        self.key = resolve_gate_key(self.state_dir, key)
        self.binding = {"gate": gate, "environment": environment}
        self._lock_path = self.state_dir / "ledger.lock"
        self._thread_lock = threading.Lock()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        record, head_problem = read_head(self.head_path, self.key)
        if head_problem is not None:
            # A corrupt/forged head must not silently reset the chain;
            # keep the on-disk chain and recommit the head from the file
            # so verification still compares apples to apples.
            _LOG.warning("authiro gate ledger head: %s", head_problem)
        self._entries, _, seq = scan_ledger_stats(self.path)
        if record is not None and record.entries > self._entries:
            # The head committed more entries than the file holds:
            # tail truncation before this process started. Keep the
            # committed count so the next append chains from the file's
            # actual tail and the mismatch stays visible to verify.
            _LOG.warning(
                "gate ledger has %d entries but head committed %d; possible truncation",
                self._entries,
                record.entries,
            )
        last = _last_line(self.path)
        self._last_hash = (last or {}).get("hash") or self._genesis()
        last_seq = (last or {}).get("seq")
        self._seq: int = last_seq if isinstance(last_seq, int) else 0
        if isinstance(seq, int) and seq > self._seq:
            self._seq = seq

    def _genesis(self) -> str:
        return GENESIS_HMAC

    # ── Appending ──────────────────────────────────────────────────────────

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Chain one event onto the ledger and recommit the head.

        Adds ``ts`` (epoch), ``seq`` (monotone), ``prev``, ``binding``
        and ``hash`` to the event and returns the written entry. The
        whole read-tail/append/recommit sequence holds an OS file lock
        so the gate and the CLI can both append safely.
        """
        with self._locked():
            last = _last_line(self.path)
            prev = (last or {}).get("hash") or self._genesis()
            prev_seq = (last or {}).get("seq")
            next_seq = (prev_seq if isinstance(prev_seq, int) else self._seq) + 1
            entry = dict(event)
            entry.setdefault("ts", time.time())
            entry["seq"] = next_seq
            entry["prev"] = prev
            entry["binding"] = self.binding
            entry["hash"] = _digest(prev, entry, self.key)
            line = _canonical(entry) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                if _fsync():
                    fh.flush()
                    os.fsync(fh.fileno())
            self._entries += 1
            self._seq = next_seq
            self._last_hash = entry["hash"]
            write_head(
                self.head_path,
                HeadRecord(self._entries, entry["hash"], self._seq),
                self.key,
            )
            return entry

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Hold the in-process lock and an OS file lock around one append.

        The thread lock serializes appends inside this process; the file
        lock (``fcntl.flock`` where available) serializes them against
        the ``authiro approve`` CLI writing to the same ledger from
        another process.
        """
        lock_file = None
        self._thread_lock.acquire()
        try:
            lock_file = self._lock_path.open("a")
            try:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            except ImportError:  # pragma: no cover - non-POSIX
                pass
            yield
        finally:
            if lock_file is not None:
                with contextlib.suppress(Exception):
                    lock_file.close()
            self._thread_lock.release()

    # ── Reading ─────────────────────────────────────────────────────────────

    def events(self) -> list[dict[str, Any]]:
        """Every ledger entry, parsed, in order."""
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    with contextlib.suppress(json.JSONDecodeError):
                        out.append(json.loads(line))
        return out

    @property
    def last_hash(self) -> str | None:
        """Hash of the most recent entry (in-process cache)."""
        return self._last_hash

    @property
    def seq(self) -> int:
        """The last committed sequence number."""
        return self._seq


def verify_gate_ledger(
    ledger_path: str | Path,
    head_path: str | Path,
    *,
    key: bytes | None = None,
    expected_binding: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Verify a gate ledger: chain, seq monotonicity, and the head file.

    Wraps :func:`verify_ledger` (edit / reorder / middle-delete / line
    corruption) and adds the head-file comparison that catches **tail
    truncation** — the ledger holding fewer entries than the committed
    head — plus a forged-head check (MAC mismatch) and an
    appended-past-the-head check.
    """
    p = Path(ledger_path)
    ok, problems = verify_ledger(p, key=key, expected_binding=expected_binding)
    resolved = resolve_gate_key(p.parent, key)
    record, head_problem = read_head(head_path, resolved)
    if head_problem is not None:
        return False, [*problems, head_problem]
    entries, head_hash, seq = scan_ledger_stats(p)
    if record is None:
        # No head commitment: warn-only through the chain result. A gate
        # that never wrote one (pre-head ledger) still verifies its chain.
        if entries and not problems:
            problems = [*problems, "no head file; truncation cannot be detected"]
        return (not problems), problems
    if entries < record.entries:
        problems.append(
            f"truncation: head file committed {record.entries} entries; ledger has "
            f"{entries} ({record.entries - entries} missing)"
        )
    elif entries > record.entries:
        problems.append(
            f"ledger has {entries} entries; head committed {record.entries} "
            f"({entries - record.entries} appended past the head)"
        )
    if head_hash is not None and head_hash != record.head_hash:
        problems.append(
            "head-file hash does not match the ledger's last entry (chain and head diverge)"
        )
    if seq is not None and record.seq is not None and seq != record.seq:
        problems.append(f"seq mismatch: ledger's last seq is {seq}; head committed {record.seq}")
    return ok and not problems, problems
