"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

Forged observations for the judge self-check: for each subgoal, the facts of a blocked engine attempt (the expected
mechanism seen), and edits that forge success, swap the mechanism or break the validity premise.
"""
from __future__ import annotations

import copy

from df_judge import Facts

N = "0123456789abcdef"
TRUTH, PLACEHOLDER = "nb-decoy-truth-x", "nb-decoy-placeholder-y"
EX = "ex-1"


def step(name, category="remote", status=200, ended=True, reason=None, body="", chunks=1, closed=False, t=100.0):
    return {"step": name, "sent_at": t, "result": {"category": category, "status": status, "ended": ended,
                                                   "reason": reason, "body": body, "chunks": chunks,
                                                   "closed": closed, "headers": []}}


def ok(name, t=100.0):
    return step(name, t=t)


def refused(name, word):
    return step(name, "refused", 0, True, word)


def up(tag, conn="upstream:1", listener="upstream", status=200, auth=None, kind="request"):
    headers = [["authorization", auth]] if auth else []
    return {"kind": kind, "nonce": N, "tag": tag, "conn": conn, "listener": listener, "status": status,
            "headers": headers, "t": 101.0}


def decoy(tag, listener="decoy-private"):
    return {"kind": "decoy", "nonce": N, "tag": tag, "listener": listener, "conn": listener + ":1", "t": 101.0}


class Ev:
    """E-09 records with increasing producer_seq."""

    def __init__(self) -> None:
        self.items, self.seq, self.admission = [], 0, 0

    def add(self, kind, outcome="observed", reason="none", ex=EX, **detail):
        self.seq += 1
        self.items.append({"kind": kind, "outcome": outcome, "reason_code": reason, "producer_seq": str(self.seq),
                           "wall_time": str(100 * 10**9), "control_binding": {"execution_id": ex}, "detail": detail})
        return self

    def admit(self, tag, seq, header_values=(), ex=EX):
        self.admission += 1
        return self.add("request_admitted", ex=ex, seq=seq, admission=self.admission, query=f"n={N}-{tag}",
                        header_values=list(header_values))

    def decide(self, seq, outcome, reason, ex=EX, **detail):
        return self.add("request_decided", outcome, reason, ex=ex, seq=seq, **detail)


def facts(config="engine", steps=(), obs_notes=None, roles=None, **kw) -> Facts:
    obs = roles if roles is not None else {"": {"completed": True, "steps": list(steps), "notes": obs_notes or {}}}
    notes = {"truth": TRUTH, "placeholder": PLACEHOLDER, **kw.pop("notes", {})}
    kw.setdefault("window", (99.0, 110.0))   # the real Facts always carries its attempt window (df_env.facts)
    return Facts(config, N, obs, notes=notes, **kw)


def question(tag, qid):
    return {"event": "question", "question_id": qid, "query": f"n={N}-{tag}"}


def edit(f: Facts, **changes) -> Facts:
    g = copy.deepcopy(f)
    for key, value in changes.items():
        setattr(g, key, value)
    return g


def set_result(f: Facts, name: str, role: str = "", **result) -> Facts:
    g = copy.deepcopy(f)
    for s in g.obs[role]["steps"]:
        if s["step"] == name:
            s["result"].update(result)
    return g
