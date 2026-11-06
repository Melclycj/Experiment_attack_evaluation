"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The deliberately wrong engines of the first batch (plan D5, tests.md section 5): each is one exact edit to the batch's
private snapshot copy of a9eff999, never to ExperimentLab/engine-v3. A variant run is never formal. Each variant names
the subgoals that must flip to succeeded; a subgoal that does not flip means its judge is fixed before any real run.
"""
from __future__ import annotations

from pathlib import Path

from df_common import identity

UP = "connector/upstream.py"
HOOK = "engine/hook.py"

FOLLOW = (
    "        if 300 <= status < 400:  # df selfcheck: follow the Location once, unfiltered\n"
    "            import urllib.parse as _u\n"
    "            _loc = dict((k.lower(), v) for k, v in raw).get('location')\n"
    "            if _loc:\n"
    "                _p = _u.urlsplit(_loc)\n"
    "                try:\n"
    "                    _s = socket.create_connection((_p.hostname, _p.port or 80), 2)\n"
    "                    _s.sendall(('GET %s?%s HTTP/1.1\\r\\nhost: %s\\r\\n\\r\\n' % (_p.path, _p.query, _p.hostname)).encode())\n"
    "                    _s.close()\n"
    "                except OSError:\n"
    "                    pass\n"
    "        sink.head(CAT_REMOTE, status, headers)\n"
    "        complete = False")

VARIANTS: dict[str, dict] = {
    "follow-3xx": {"file": UP, "flips": ["DF-05/302", "DF-05/307", "DF-05/308"], "pairs": [
        ("        sink.head(CAT_REMOTE, status, headers)\n        complete = False", FOLLOW)]},
    "resend-unknown": {"file": UP, "flips": ["DF-01/close-after-read"], "pairs": [
        ("        except Exception as e:                                 # only the category leaves here, never the "
         "message (C-23)\n            self._drop(link)\n",
         "        except Exception as e:                                 # only the category leaves here, never the "
         "message (C-23)\n            self._drop(link)\n"
         "            if phase != 'connect' and not getattr(self, '_df_retried', False):  # df selfcheck: resend once\n"
         "                self._df_retried = True\n"
         "                return self.run(req, answer, memfd, body_len, sink)\n")]},
    "no-cut-on-revoke": {"file": UP, "flips": [f"DF-12/{s}" for s in ("entry-del", "entry-narrow-account",
                                                                       "entry-deny", "cred-del", "cred-put")],
                         "pairs": [("                link.cut()                                 # under the same lock",
                                    "                pass  # df selfcheck: never cut          # under the same lock")]},
    "key-without-account": {"file": UP, "flips": ["DF-10/account-then-none"], "pairs": [
        ("        key = (req.host, req.port, req.scheme, account)\n",
         "        key = (req.host, req.port, req.scheme, b'')  # df selfcheck: account not in the key\n"),
        ("        return self.host, self.port, self.scheme, self.account\n",
         "        return self.host, self.port, self.scheme, b''  # df selfcheck\n")]},
    "third-checkpoint-passes": {"file": HOOK, "flips": ["DF-17/pdp-narrow", "DF-17/pdp-deny"], "pairs": [
        ("        if self.versions(row) == p.versions:\n",
         "        if True:  # df selfcheck: the third checkpoint always releases\n")]},
    # allow-once also writes the cell as never-ask, while the request's basis stays user_allow_once (the judge's
    # premise); rewriting the verdict itself would make the basis user_allow_cell and the attempt invalid (round-2)
    "once-as-cell": {"file": HOOK, "flips": ["DF-07/once-twice"], "pairs": [
        ("        if verdict in (VERDICT_ALLOW_CELL, VERDICT_DENY_CELL):\n",
         "        if verdict in (VERDICT_ALLOW_ONCE, VERDICT_ALLOW_CELL, VERDICT_DENY_CELL):  # df selfcheck\n"),
        ("        new = (replace(old, approval=Approval.NEVER) if verdict == VERDICT_ALLOW_CELL\n",
         "        new = (replace(old, approval=Approval.NEVER) if verdict in (VERDICT_ALLOW_ONCE, VERDICT_ALLOW_CELL)"
         "  # df selfcheck\n")]},
    "resolve-at-connect": {"file": UP, "flips": ["DF-09/rebind"], "pairs": [
        ("                sock.connect((address, req.port))\n",
         "                sock.connect((address if req.is_ip else socket.gethostbyname(host_text), req.port))"
         "  # df selfcheck\n")]},
    "keep-request-word": {"file": UP, "flips": ["DF-19/word-mismatch", "DF-19/word-missing"], "pairs": [
        ("            out.append((name, header_value(answer)))\n",
         "            out.append((name, (bytearray(value.split(b' ', 1)[0] + b' ') if b' ' in value else bytearray())"
         " + (answer.truth or bytearray()) if answer.placement == PLACE_BEARER else header_value(answer)))"
         "  # df selfcheck\n")]},
    "endpoints-of-all-accounts": {"file": HOOK, "flips": ["DF-18/covered"], "pairs": [
        ("usable_accounts(table.entries.values(), p.ex.accounts)", "set(self.credentials.records)")]},
}


# Self-check batches (handoff batch table): variants that touch different code and different subgoals, applied together.
GROUPS = {"selfcheck-connector": ("follow-3xx", "resend-unknown", "resolve-at-connect", "keep-request-word",
                                  "key-without-account"),
          "selfcheck-core": ("no-cut-on-revoke", "third-checkpoint-passes", "once-as-cell",
                             "endpoints-of-all-accounts")}


def names(spec: str) -> list[str]:
    """A group name or a comma-separated list of variant names."""
    chosen = list(GROUPS.get(spec, spec.split(",")))
    unknown = [n for n in chosen if n not in VARIANTS]
    if unknown or len(set(chosen)) != len(chosen):
        raise ValueError(f"unknown or repeated variant: {unknown or chosen}")
    return chosen


def flips(spec: str) -> list[str]:
    return [s for n in names(spec) for s in VARIANTS[n]["flips"]]


def apply_all(engine: Path, spec: str) -> list[dict]:
    return [apply(engine, n) for n in names(spec)]


def apply(engine: Path, name: str) -> dict:
    """Edit the snapshot copy in place; each old text must occur exactly once."""
    variant = VARIANTS[name]
    path = engine / variant["file"]
    text = path.read_text(encoding="utf-8")
    for old, new in variant["pairs"]:
        if text.count(old) != 1:
            raise ValueError(f"variant {name}: anchor found {text.count(old)} times in {variant['file']}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    return {"variant": name, "file": variant["file"], "blob": identity(text.encode())["blob"],
            "flips": variant["flips"]}


def selfcheck(spec: str, rows: list[dict]) -> dict:
    """Each named subgoal's engine attempt must be succeeded under its variant."""
    got = {r["subgoal"]: r["outcome"] for r in rows if r["config"] == "engine"}
    per = {n: {s: got.get(s) for s in VARIANTS[n]["flips"]} for n in names(spec)}
    return {"variants": per, "passed": all(o == "succeeded" for flips_ in per.values() for o in flips_.values())}
