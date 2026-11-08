"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

One attempt = one subgoal under one configuration. Engine: reset the table to the fallback alone, set up over the
management port, start the row(s), let the driver act, wait for the row to close, read the facts, judge. Undefended:
the same request, run by the same runner as the host user straight against the test network. Each attempt has a
fresh nonce and a fresh test credential; its clock starts at the first row (tests.md 1.1: 30 s, DF-06 no-answer 360 s).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import threading
import time
import traceback

from df_common import (ACCOUNT_A, ACCOUNT_Y, ALT_PORT, HOST_UID, OPEN_HOST, OWNER_UID, UP_HOST, UP_IP, UP_KEY,
                       digest, utc)
from df_deploy import PLANS, PYTHON, TREE
from df_judge import Facts, admitted, owner
from df_proc import AS_HOST
from df_safeio import read_beneath

RESET_KEYS = (UP_KEY, f"{UP_HOST}:{ALT_PORT}", f"{OPEN_HOST}:443")
RESET_CREDS = ((UP_KEY, ACCOUNT_A), (UP_KEY, ACCOUNT_Y))
POLL = 0.05


class Attempt:
    """What a driver may do; everything it does lands in notes."""

    def __init__(self, env, case, config: str) -> None:
        self.env, self.case, self.config = env, case, config
        self.engine = config == "engine"
        self.nonce = secrets.token_hex(8)
        self.truth = "nb-decoy-truth-" + secrets.token_hex(16)
        self.notes: dict = {"truth": self.truth, "placeholder": "nb-decoy-placeholder-" + secrets.token_hex(8)}
        self.executions: list[str] = []
        self.ev_offset = env.events.offset()
        self.q_index = len(env.watch.events) if env.watch else 0
        self.pdp_index = len(env.pdp.events)
        self.admin_index = len(env.admin.log) if env.admin else 0
        self.start, self.end = time.time(), None
        self.works = [env.uwork] if not self.engine else [env.root / ws / TREE for ws, _ in case.rows]

    @property
    def admin(self):
        """The management port, as drivers use it (ctl.admin.entry_put ...)."""
        return self.env.admin

    @property
    def watch(self):
        """The approval window, as drivers use it (ctl.watch.withdrawn ...)."""
        return self.env.watch

    def mark_window(self) -> None:
        """Facts start here: E-09, approval-window, PDP and admin records before this belong to the preparation."""
        self.ev_offset = self.env.events.offset()
        self.q_index = len(self.env.watch.events) if self.env.watch else 0
        self.pdp_index = len(self.env.pdp.events)
        self.admin_index = len(self.env.admin.log) if self.env.admin else 0

    # ---- synchronisation with the runner -------------------------------------------------------------------------
    def wait_mark(self, name: str, limit: float = 10.0) -> bool:
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if any((w / f"df-{self.nonce}-mark-{name}").exists() for w in self.works):
                self.notes.setdefault("marks_seen", []).append([name, time.time()])
                return True
            time.sleep(POLL)
        self.notes.setdefault("marks_missed", []).append(name)
        return False

    def go(self, name: str) -> None:
        """The runner only tests that the file exists (directory search right suffices), so no chown is needed."""
        for w in self.works:
            (w / f"df-{self.nonce}-go-{name}").write_text("go")
        self.notes.setdefault("released", []).append([name, time.time()])

    # ---- the user's side -----------------------------------------------------------------------------------------
    def op(self, key: str, receipt: dict) -> dict:
        self.notes[key] = receipt
        return receipt

    def question(self, tag: str, limit: float, after: int = 0) -> dict | None:
        return self.env.watch.question(f"{self.nonce}-{tag}", limit, after)

    def answer(self, question: dict, verdict: str, key: str | None = None) -> dict:
        reply = self.env.admin.answer(question["question_id"], verdict)
        self.notes.setdefault("answers", []).append({"question_id": question["question_id"], "verdict": verdict,
                                                     "reply": reply})
        if key:
            self.notes[key] = reply
        return reply

    def fresh_truth(self) -> bytes:
        self.notes["truth_replaced"] = True
        return ("nb-decoy-truth-" + secrets.token_hex(16)).encode()

    def note(self, key: str, value) -> None:
        self.notes[key] = value

    # ---- E-09, the PDP stand-in, the upstream ----------------------------------------------------------------------
    def events(self) -> list[dict]:
        return self.env.events.read_from(self.ev_offset)

    def record(self, kind: str, limit: float, **match) -> dict | None:
        end = time.monotonic() + limit
        while time.monotonic() < end:
            for e in self.events():
                d = e.get("detail") or {}
                if e.get("kind") == kind and all(d.get(k) == v for k, v in match.items()):
                    return e
            time.sleep(POLL)
        return None

    def withdrawn_record(self, tag: str, limit: float) -> dict | None:
        end = time.monotonic() + limit
        while time.monotonic() < end:
            view = Facts(self.config, self.nonce, {}, events=self.events())
            keys = {(owner(a), a["detail"]["seq"]) for a in admitted(view, tag)}
            for e in view.events:
                if e.get("kind") == "request_withdrawn" and (owner(e), e["detail"].get("seq")) in keys:
                    return e
            time.sleep(POLL)
        return None

    def connector_event(self, event: str, limit: float, at_least: int = 1) -> dict | None:
        """The connector's own record of having applied something (its stderr log, df_connector_log.py): for a
        revocation the line {"event": "revoked", "connections": n}, written after Registry.revoke returned; n is the
        number of links it matched and called cut() on, not a count of verified cuts."""
        end = time.monotonic() + limit
        while time.monotonic() < end:
            for ex in self.executions:
                for line in self.env.connector_lines(ex):
                    if line.get("event") == event and int(line.get("connections", 0)) >= at_least:
                        return line
            time.sleep(POLL)
        return None

    def pdp_event(self, event: str, limit: float) -> dict | None:
        return self.env.pdp.wait(lambda e: e.get("event") == event and f"n={self.nonce}-a" in e.get("query", ""),
                                 self.pdp_index, limit)

    def pdp_release(self) -> None:
        self.env.pdp.release()
        self.notes["pdp_released_at"] = time.time()

    def release_stream(self, limit: float = 5.0) -> None:
        """Open the upstream's gate, then wait until the upstream has logged its second block (sent, or failed on a
        cut connection): a correctly cut stream lets the runner exit at once, and the facts must not be read before
        that line exists (round-2 review, finding 1)."""
        self.env.net.gate_stream(self.nonce)
        self.notes["stream_released_at"] = time.time()
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if any(r.get("kind") == "block" and r.get("block") == 2 and r.get("nonce") == self.nonce
                   for r in self.env.net.read("test")):
                self.notes["second_block_logged"] = True
                return
            time.sleep(POLL)
        self.notes["second_block_logged"] = False


def request(case, attempt: Attempt, config: str, role: str | None, targets: dict) -> bytes:
    body = {"attack": case.attack, "sub": case.sub, "nonce": attempt.nonce, "config": config, "role": role,
            "targets": {**targets, "placeholder": attempt.notes["placeholder"]}, **case.extra}
    return json.dumps(body).encode()


def clear(work: Path) -> None:
    for p in work.iterdir():
        if p.name.startswith("df-"):
            p.unlink()


def reset_table(env) -> list:
    out = []
    for ws in ("work0", "work1"):
        for key in RESET_KEYS:
            out.append(env.admin.entry_del(ws, key))
    for host_port, account in RESET_CREDS:
        out.append(env.admin.cred_del(host_port, account))
    for ws in ("work0", "work1"):
        mirror = json.loads((env.root / "state" / "workspaces" / f"{ws}.json").read_text())
        if [e.get("key") for e in mirror["entries"]] != [""]:
            raise RuntimeError(f"{ws} table is not the fallback alone after the reset")
    return out


def setup(env, attempt: Attempt) -> None:
    receipts = []
    for item in attempt.case.setup:
        if item[0] == "entry":
            _, ws, key, kw = item
            receipts.append(env.admin.entry_put(ws, key, **kw))
        else:
            _, account, endpoint = item
            receipts.append(env.admin.cred_put(UP_KEY, account, attempt.truth.encode(), token_endpoint=endpoint))
    attempt.notes["setup"] = receipts
    failed = [r["verb"] for r in receipts if not r["ok"]]
    if failed:
        attempt.notes["setup_failed"] = failed


def start_driver(attempt: Attempt) -> threading.Thread | None:
    if attempt.case.driver is None:
        return None

    def run() -> None:
        try:
            attempt.case.driver(attempt)
        except Exception as e:                          # recorded; the judge then sees the missing notes
            attempt.notes["driver_error"] = f"{type(e).__name__}: {e}"
            attempt.notes["driver_traceback"] = traceback.format_exc()[-3000:]
    t = threading.Thread(target=run, name="df-driver", daemon=True)
    t.start()
    return t


def run_engine(env, case) -> tuple[Attempt, Facts]:
    a = Attempt(env, case, "engine")
    roles = []
    try:
        a.notes["reset"] = [r["ok"] for r in reset_table(env)]
        for w in a.works:
            clear(w)
        setup(env, a)
        a.mark_window()                                 # the reset's and the setup's own records stay out of the facts
        if case.dns_epoch:
            env.net.new_dns_epoch(a.nonce)
            a.notes["first_answer"] = UP_IP
        if case.mirror:
            a.notes["mirror_before"] = digest(json.loads(mirror_path(env).read_text()))
        env.pdp.use(case.pdp)
        if case.pdp == "hold":
            env.pdp.arm(f"{a.nonce}-a")
        a.start = time.time()
        deadline = time.monotonic() + case.limit
        driver = start_driver(a)
        for ws, role in case.rows:
            work = env.root / ws / TREE
            path = work / "df-request.json"
            path.write_bytes(request(case, a, "engine", role, env.targets))
            os.chown(path, OWNER_UID, OWNER_UID)
            started = env.admin.row_start(ws, PLANS[ws])
            if not started["ok"]:
                a.notes["row_start_failed"] = started
                break
            execution = started["payload"][0]
            a.executions.append(execution)
            roles.append(role or "")
            env.wait_row(execution, work / obs_name(a.nonce, role), deadline, a.notes)
        if driver is not None:
            driver.join(max(0.0, deadline - time.monotonic()))
            if driver.is_alive():
                a.notes["driver_timeout"] = True
        if case.mirror:
            a.notes["mirror_after"] = digest(json.loads(mirror_path(env).read_text()))
    except Exception as e:
        a.notes["controller_error"] = f"{type(e).__name__}: {e}"
        a.notes["controller_traceback"] = traceback.format_exc()[-3000:]
    a.end = time.time()
    return a, safe_facts(env, a, roles or [r or "" for _, r in case.rows])


def run_undefended(env, case) -> tuple[Attempt, Facts]:
    a = Attempt(env, case, "undefended")
    try:
        clear(env.uwork)
        targets = {**env.targets, "ca_file": str(env.uwork / "nb-decoy-ca.pem")}
        shutil.copyfile(env.ca_file, env.uwork / "nb-decoy-ca.pem")
        os.chmod(env.uwork / "nb-decoy-ca.pem", 0o644)
        (env.uwork / "df-request.json").write_bytes(request(case, a, "undefended", None, targets))
        if case.dns_epoch:
            env.net.new_dns_epoch(a.nonce)
            a.notes["first_answer"] = UP_IP
        a.start = time.time()
        driver = start_driver(a)
        err = (env.scratch / f"nb-decoy-undefended-{a.nonce}.stderr").open("wb")
        proc = env.command.start(AS_HOST + PYTHON + [env.scripts / "df_runner.py"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=err, cwd=str(env.uwork),
                                 env={"DF_WORK": str(env.uwork), "DF_TRUTH": a.truth, "HOME": str(env.uwork)})
        try:
            a.notes["runner_exit"] = proc.wait(timeout=case.limit)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
            a.notes["attempt_timeout"] = True
        err.close()
        if driver is not None:
            driver.join(5)
            if driver.is_alive():
                a.notes["driver_timeout"] = True
    except Exception as e:
        a.notes["controller_error"] = f"{type(e).__name__}: {e}"
        a.notes["controller_traceback"] = traceback.format_exc()[-3000:]
    a.end = time.time()
    return a, safe_facts(env, a, [""])


def safe_facts(env, attempt: Attempt, roles: list[str]) -> Facts:
    """A failure to read the facts loses this attempt only (tests.md 1.4), never the batch."""
    try:
        return env.facts(attempt, roles)
    except Exception as e:
        attempt.notes["controller_error"] = f"facts unreadable: {type(e).__name__}: {e}"
        return Facts(attempt.config, attempt.nonce, {}, notes=attempt.notes, executions=list(attempt.executions))


def obs_name(nonce: str, role: str | None) -> str:
    return f"df-{nonce}{'-' + role if role else ''}-obs.json"


def mirror_path(env) -> Path:
    return env.root / "state" / "workspaces" / "work0.json"


def read_obs(work: Path, nonce: str, role: str | None) -> dict | None:
    try:
        return json.loads(read_beneath(work, obs_name(nonce, role)))
    except (FileNotFoundError, ValueError):
        return None


def host_work(directory: Path) -> Path:
    """The undefended runner's work directory: the host user's, 0700 (its HOME during the attempt)."""
    directory.mkdir(mode=0o700)
    os.chown(directory, HOST_UID, HOST_UID)
    return directory


def stamp(attempt: Attempt) -> dict:
    return {"nonce": attempt.nonce, "config": attempt.config, "executions": attempt.executions,
            "started_at": attempt.start, "finished_at": attempt.end, "utc": utc()}
