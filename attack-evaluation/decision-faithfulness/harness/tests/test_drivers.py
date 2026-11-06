"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Every controller driver run against a fake engine environment under both configurations: no driver error, the
management-port calls the subgoal needs (engine) or none (undefended), and the notes its judge reads. A driver that
reached for something the attempt does not have was a real-run failure the other tests could not see (round-2
recheck: ctl.admin and ctl.watch were missing).
"""
from __future__ import annotations

import inspect

import pytest

import df_admin
import df_control
from df_deploy import TREE
from df_registry import REGISTRY

DRIVEN = sorted(cid for cid, c in REGISTRY.items() if c.driver is not None)


class FakeAdmin:
    """Accepts only the real df_admin.Admin verbs, with arguments that bind to their signatures and enumeration
    values the real tables know (round-2 recheck: a fake that accepts anything hides misspelt verbs)."""

    def __init__(self) -> None:
        self.log, self.calls = [], []

    def __getattr__(self, verb):
        real = getattr(df_admin.Admin, verb)          # AttributeError for a verb the real client lacks
        signature = inspect.signature(real)

        def call(*args, **kwargs):
            bound = signature.bind(None, *args, **kwargs)
            checks = {"state": df_admin.STATES, "approval": df_admin.APPROVALS, "kind": df_admin.KEY_KINDS,
                      "verdict": df_admin.VERDICTS}
            for name, table in checks.items():
                if name in bound.arguments and bound.arguments[name] not in table:
                    raise KeyError(f"{verb}: {name}={bound.arguments[name]!r}")
            if verb == "cred_put" and not isinstance(bound.arguments["truth"], bytes):
                raise TypeError("cred_put truth must be bytes")
            self.calls.append((verb, args, kwargs))
            return {"verb": verb, "ok": True, "detail": "", "payload": []}
        return call


class FakeWatch:
    def __init__(self) -> None:
        self.events, self.next = [], 0

    def question(self, tag, limit, after=0):
        self.next += 1
        return {"event": "question", "question_id": after + self.next, "query": f"n={tag}"}

    def withdrawn(self, question_id, limit):
        return {"event": "withdrawn", "question_id": question_id, "reason": 1}


class FakeEvents:
    def __init__(self) -> None:
        self.records = []

    def offset(self):
        return 0

    def read_from(self, index):
        return self.records[index:]


class FakePdp:
    def __init__(self) -> None:
        self.events, self.released = [], 0

    def wait(self, predicate, index, limit):
        return {"event": "held", "admission": 7, "query": "held"}

    def release(self):
        self.released += 1


class FakeNet:
    def __init__(self) -> None:
        self.gated, self.nonce = [], None

    def gate_stream(self, nonce):
        self.gated.append(nonce)

    def read(self, side):
        return [{"kind": "block", "block": 2, "nonce": n, "sent": True} for n in self.gated]


class FakeEnv:
    def __init__(self, root) -> None:
        self.root, self.uwork = root, root / "uwork"
        self.uwork.mkdir()
        for ws in ("work0", "work1"):
            (root / ws / TREE).mkdir(parents=True)
        self.admin, self.watch, self.events = FakeAdmin(), FakeWatch(), FakeEvents()
        self.pdp, self.net = FakePdp(), FakeNet()

    def connector_lines(self, execution):
        return [{"event": "revoked", "connections": 1}]


def attempt_for(tmp_path, cid, config):
    env = FakeEnv(tmp_path)
    case = REGISTRY[cid]
    a = df_control.Attempt(env, case, config)
    a.executions.append("ex-1")
    for w in a.works:                                  # every mark a driver may wait for, already made
        for mark in ("controlled", "sent-a", "first"):
            (w / f"df-{a.nonce}-mark-{mark}").write_text("1")
    env.events.records += [
        {"kind": "entry_revoked", "detail": {}},
        {"kind": "table_changed", "detail": {"key": "nb-decoy-up:443", "verb": "put"}},
        {"kind": "table_changed", "detail": {"key": "nb-decoy-open:443", "verb": "put"}},
        {"kind": "request_admitted", "control_binding": {"execution_id": "ex-1"},
         "detail": {"seq": 2, "query": f"n={a.nonce}-a"}},
        {"kind": "request_withdrawn", "control_binding": {"execution_id": "ex-1"}, "detail": {"seq": 2}}]
    return env, a


@pytest.mark.parametrize("config", ["engine", "undefended"])
@pytest.mark.parametrize("cid", DRIVEN)
def test_driver_runs_without_error(tmp_path, cid, config):
    """Through the real thread wrapper, so an exception lands in driver_error as it would in a batch."""
    env, a = attempt_for(tmp_path, cid, config)
    thread = df_control.start_driver(a)
    thread.join(30)
    assert not thread.is_alive()
    assert "driver_error" not in a.notes, a.notes.get("driver_error")
    if config == "undefended":
        assert not [c for c in env.admin.calls if c[0] != "row_list"], env.admin.calls


EXPECTED_CALLS = {
    "DF-03/recorded-deny": {"entry_put"}, "DF-06/deny": {"answer"}, "DF-06/no-answer": {"answer"},
    "DF-07/once-twice": {"answer"}, "DF-08/withdraw-swap": {"answer"},
    "DF-12/entry-del": {"entry_del"}, "DF-12/entry-narrow-account": {"entry_put"}, "DF-12/entry-deny": {"entry_put"},
    "DF-12/cred-del": {"cred_del"}, "DF-12/cred-put": {"cred_put"}, "DF-17/ask-then-narrow": {"entry_put", "answer"},
    "DF-17/pdp-narrow": {"entry_put"}, "DF-17/pdp-deny": {"entry_put"}, "PC-ONCE": {"answer"},
    "PC-CELL": {"answer"}, "PC-RECHECK": {"entry_put"}, "PC-STREAM": set()}
NOTES = {
    "DF-08/withdraw-swap": {"question_a", "withdrawn_before_answer", "answer_a", "question_b"},
    "DF-17/ask-then-narrow": {"question_a", "table_changed_before_answer", "answer_a"},
    "DF-17/pdp-narrow": {"held", "table_changed"}, "DF-17/pdp-deny": {"held", "table_changed"},
    "PC-RECHECK": {"held", "table_changed"}, "DF-07/once-twice": {"second_question", "second_withdrawal"},
    **{f"DF-12/{s}": {"entry_revoked", "connector_revoked", "second_block_logged"}
       for s in ("entry-del", "entry-narrow-account", "entry-deny", "cred-del", "cred-put")}}


@pytest.mark.parametrize("cid", DRIVEN)
def test_engine_driver_makes_its_calls_and_notes(tmp_path, cid):
    env, a = attempt_for(tmp_path, cid, "engine")
    REGISTRY[cid].driver(a)
    assert EXPECTED_CALLS[cid] <= {c[0] for c in env.admin.calls}, env.admin.calls
    missing = {k for k in NOTES.get(cid, ()) if not a.notes.get(k)}
    assert not missing, (cid, missing)
    if cid.startswith(("DF-17/pdp", "PC-RECHECK")):
        assert env.pdp.released == 1
    if cid.startswith(("DF-12/", "PC-STREAM")):
        assert env.net.gated == [a.nonce] and a.notes["second_block_logged"]


def test_every_driver_has_expectations():
    assert set(DRIVEN) == set(EXPECTED_CALLS)
