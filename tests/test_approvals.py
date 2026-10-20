"""Signed approvals: keygen, approve flow, forgery, replay, expiry."""

from __future__ import annotations

import sqlite3
import time

import pytest

from authiro.approvals import (
    APPROVED,
    CONSUMED,
    PENDING,
    ApprovalStore,
    generate_key_pair,
    sign_payload,
    verify_signature,
)
from authiro.risk import args_hash


@pytest.fixture()
def keys(tmp_path):
    private, public = generate_key_pair(tmp_path, prefix="test-approver")
    return private.read_bytes(), public.read_bytes()


@pytest.fixture()
def store(tmp_path, keys):
    _, public = keys
    return ApprovalStore(
        tmp_path / "approvals.db",
        gate="test-gate",
        environment="staging",
        ttl=900,
        public_key_pem=public,
    )


@pytest.fixture()
def signer(tmp_path, keys):
    private, _ = keys

    def _sign(payload: str) -> str:
        return sign_payload(private, payload)

    return _sign


def _args():
    return {"volume_id": "stg-db"}


def test_generate_key_pair_writes_private_and_public(tmp_path):
    private, public = generate_key_pair(tmp_path)
    assert private.exists() and public.exists()
    assert private.stat().st_mode & 0o777 == 0o600
    assert b"PRIVATE KEY" in private.read_bytes()
    assert b"PUBLIC KEY" in public.read_bytes()


def test_sign_and_verify_roundtrip(keys):
    private, public = keys
    payload = '{"id":"abc","tool":"cloud_delete_volume"}'
    sig = sign_payload(private, payload)
    assert sig
    assert verify_signature(public, payload, sig)
    assert not verify_signature(public, payload + "tampered", sig)


def test_get_or_create_is_idempotent_while_pending(store):
    a = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    b = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    assert a.id == b.id
    assert a.status == PENDING


def test_approve_and_consume_flow(store, signer):
    request = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    approved = store.approve(request.id, signer(request.payload))
    assert approved.status == APPROVED
    assert store.has_valid_approval("cloud_delete_volume", args_hash(_args()))
    ok, consumed, why = store.consume("cloud_delete_volume", args_hash(_args()))
    assert ok, why
    assert consumed.status == CONSUMED


def test_approval_is_single_use(store, signer):
    request = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    store.approve(request.id, signer(request.payload))
    ok, _, _ = store.consume("cloud_delete_volume", args_hash(_args()))
    assert ok
    ok2, _, why2 = store.consume("cloud_delete_volume", args_hash(_args()))
    assert not ok2
    assert why2 == "no approved request for this call"


def test_approval_binds_to_exact_args(store, signer):
    request = store.get_or_create(
        "cloud_delete_volume",
        args_hash({"volume_id": "stg-db"}),
        risk="destructive",
        args_redacted={"volume_id": "stg-db"},
    )
    store.approve(request.id, signer(request.payload))
    # A different call must not see this approval
    assert not store.has_valid_approval("cloud_delete_volume", args_hash({"volume_id": "prod-db"}))
    ok, _, _ = store.consume("cloud_delete_volume", args_hash({"volume_id": "prod-db"}))
    assert not ok


def test_forged_row_is_rejected_and_named(store, tmp_path):
    """The agent flips a pending row to 'approved' in sqlite directly."""
    request = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    conn = sqlite3.connect(store.db_path)
    conn.execute(
        "UPDATE approval_requests SET status='approved', signature='bogus', "
        "approved_at=?, expires_at=? WHERE id=?",
        (time.time(), time.time() + 9999, request.id),
    )
    conn.commit()
    conn.close()
    assert not store.has_valid_approval("cloud_delete_volume", args_hash(_args()))
    ok, _forged, why = store.consume("cloud_delete_volume", args_hash(_args()))
    assert not ok
    assert "signature" in why


def test_expired_approval_does_not_count(store, signer, monkeypatch):
    import time as _time

    request = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    store.approve(request.id, signer(request.payload))
    # fast-forward past the TTL
    real_time = _time.time
    monkeypatch.setattr(_time, "time", lambda: real_time() + 901)
    assert not store.has_valid_approval("cloud_delete_volume", args_hash(_args()))
    ok, _, why = store.consume("cloud_delete_volume", args_hash(_args()))
    assert not ok
    assert why == "approval expired"


def test_denied_request_cannot_be_approved(store, signer):
    request = store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    store.deny(request.id)
    with pytest.raises(ValueError, match="denied"):
        store.approve(request.id, signer(request.payload))
    ok, _, _ = store.consume("cloud_delete_volume", args_hash(_args()))
    assert not ok


def test_pending_listing(store):
    store.get_or_create(
        "cloud_delete_volume", args_hash(_args()), risk="destructive", args_redacted=_args()
    )
    pending = store.pending()
    assert len(pending) == 1
    assert pending[0].tool == "cloud_delete_volume"
    assert pending[0].args_redacted == _args()


def test_signature_from_wrong_key_is_rejected(tmp_path, keys, signer):
    _, public = keys
    other_private, _ = generate_key_pair(tmp_path, prefix="other")
    payload = '{"id":"x"}'
    bad_sig = sign_payload(other_private.read_bytes(), payload)
    assert not verify_signature(public, payload, bad_sig)
