"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The repin to registered baseline v4 (engine-v3 at a9eff999; plan attack-eval-v4-formal step 4), checked offline against
the pinned code itself: the management verbs this harness sends are frames the pinned engine reads (ENTRY_PUT has nine
fields there), the catalog carries exactly the keys the pinned catalog.c requires (the file worker, the MCP server and
its port among them), the MCP server is built and its uid reserved, and the formal check holds a host-readings profile
to the same conditions as the 1.1/2.3 apparatus (CONFIG digest, required set).
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import threading

import pytest

import df_admin
import df_baseline
import df_cleanup
import df_deploy
import df_common as dc            # read per test, so a missing constant fails that test, not the module

REPO = Path(__file__).resolve().parents[7]          # tests -> harness -> unit -> ... -> repository root (conftest.REPO)


def pinned(path: str) -> str:
    return subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(REPO), "show",
                           f"{dc.ENGINE_COMMIT}:{dc.ENGINE_PATH}/{path}"],
                          capture_output=True, check=True, text=True).stdout


# ---- the pin -----------------------------------------------------------------------------------------------------------
def test_pin_is_the_registered_v4():
    versions = json.loads((REPO / df_baseline.BASE / "versions.json").read_text(encoding="utf-8"))
    assert dc.BASELINE == "v4"
    assert versions[dc.BASELINE]["engine_path"] == dc.ENGINE_PATH
    assert versions[dc.BASELINE]["engine_commit"] == dc.ENGINE_COMMIT and len(dc.ENGINE_COMMIT) == 40


# ---- the management verbs against the pinned port's framing ------------------------------------------------------------
class FakePort(threading.Thread):
    """The engine's side of link D as the pinned engine reads it (engine/admin.py: FrameParser over LINK_D_TO_CORE):
    every frame is parsed with the pinned canonical, kept, and answered OK."""

    def __init__(self, c, path: Path) -> None:
        super().__init__(daemon=True)
        self.c, self.frames, self.errors = c, [], []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(8)

    def run(self) -> None:
        c = self.c
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            parser = c.FrameParser(c.LIMITS.frame_bd, c.LINK_D_TO_CORE)
            with conn:
                while data := conn.recv(65536):
                    try:
                        for kind, fields in parser.feed(data):
                            self.frames.append((kind, fields))
                            conn.sendall(c.pack_frame(c.OK, [c.u8(kind), c.pack_list([])]))
                    except Exception as error:          # noqa: BLE001 - kept for the assertion
                        self.errors.append(repr(error))
                        break


def test_admin_verbs_are_frames_the_pinned_engine_reads(engine_snapshot, tmp_path):
    (tmp_path / "state").mkdir()
    admin = df_admin.Admin(tmp_path, engine_snapshot)
    port = FakePort(admin.c, tmp_path / "state" / "admin.sock")
    port.start()
    try:
        replies = [admin.entry_put("work0", "nb-decoy-up:443", methods=["POST"], prefixes=["/ok"],
                                   accounts=["nb-decoy-acct-a"], approval="always"),
                   admin.entry_put("work0", "nb-decoy-up:443", state="deny"),
                   admin.entry_del("work0", "nb-decoy-up:443"),
                   admin.cred_put("nb-decoy-up:443", "nb-decoy-acct-y", b"nb-decoy-truth",
                                  token_endpoint="https://nb-decoy-up/oauth/token"),
                   admin.cred_del("nb-decoy-up:443", "nb-decoy-acct-y"),
                   admin.row_start("work0", "df-runner-0"), admin.row_list(), admin.row_stop("ex-1"),
                   admin.answer(1, "allow-once")]
    finally:
        port.server.close()
    c = admin.c
    assert all(r["ok"] for r in replies) and not port.errors
    assert [k for k, _ in port.frames] == [c.ENTRY_PUT, c.ENTRY_PUT, c.ENTRY_DEL, c.CRED_PUT, c.CRED_DEL,
                                           c.ROW_START, c.ROW_LIST, c.ROW_STOP, c.ANSWER]
    assert all(len(fields) == c.FIELD_COUNT[kind] for kind, fields in port.frames)
    import engine.admin as core_admin                    # the pinned engine's own reading of ENTRY_PUT (K-57)
    assert Path(core_admin.__file__).resolve().is_relative_to(engine_snapshot.resolve())
    for kind, f in port.frames[:2]:
        entry = core_admin.make_entry(c.read_uint(f[1], 1), core_admin.text(f[2]), c.read_uint(f[3], 1),
                                      core_admin.texts(f[4]), core_admin.texts(f[5]), core_admin.texts(f[6]),
                                      c.read_uint(f[7], 1), core_admin.texts(f[8]))
        assert entry.addresses == ()                     # this unit names no non-global address


# ---- the catalog, the seed and the build against the pinned code -------------------------------------------------------
def services(tmp_path: Path) -> dict:
    return df_deploy.services(Path("/e"), tmp_path, Path("/h"), Path("/logs"), "/ca.pem",
                              ["/runtime/frontend/engine-frontend", "--ca-dir", "/w2/ca"])


def test_catalog_keys_are_those_of_the_pinned_catalog_c(tmp_path):
    body = re.search(r"catalog_keys\[\]=\{(.*?)\};", pinned("native/sandbox/catalog.c"), re.S).group(1)
    required = set(re.findall(r'"([a-z_]+)"', body))
    assert {"file_worker", "mcp_server", "mcp_port"} <= required
    assert set(df_deploy.ARTIFACT_KEYS) | set(services(tmp_path)) == required


def test_file_worker_and_mcp_server_as_the_pinned_gate_places_them(tmp_path):
    s = services(tmp_path)
    sandbox, seed = pinned("native/checks/run_sandbox_checks.py"), pinned("checks/gate_seed.py")
    assert int(re.search(r"^WORKER_ID = (\d+)", sandbox, re.M)[1]) == dc.WORKER_UID == 70996
    assert int(re.search(r"^MCP_PORT = (\d+)", sandbox, re.M)[1]) == dc.MCP_PORT == s["mcp_port"] != s["proxy_port"]
    assert s["file_worker"]["uid"] == s["file_worker"]["gid"] == dc.WORKER_UID
    assert s["file_worker"]["argv"][-3:] == ["/e/bin/file-worker", "--library", str(tmp_path / "libw2sandbox.so")]
    assert pinned("bin/file-worker").startswith("#!")
    assert re.search(r"^MCP_SEED = '(.*)'", seed, re.M)[1] == df_deploy.MCP_SEED
    assert s["mcp_server"] == {"executable": "/runtime/" + df_deploy.MCP_SEED, "argv": ["/runtime/" + df_deploy.MCP_SEED]}
    assert re.search(r"^MCP_BUILD = (\[.*\])", seed, re.M)[1].replace("'", '"') == json.dumps(df_deploy.MCP_BUILD)
    assert s["connector"]["argv"][-2:] == ["--ca-file", "/ca.pem"] and s["runtime_mode"] == "shared"


def test_compile_builds_the_mcp_server(tmp_path):
    calls = []
    df_deploy.compile_engine(Path("/e"), tmp_path, lambda argv, **kw: calls.append((list(map(str, argv)), kw)), "/h")
    mcp = [argv for argv, kw in calls if "/e/mcp-go" in argv and kw.get("in_cgroup")]
    assert len(mcp) == 1 and mcp[0][-3:] == ["-o", str(tmp_path / "engine-mcp"), "."]
    assert mcp[0][mcp[0].index("/e/mcp-go") + 1:][:len(df_deploy.MCP_BUILD)] == df_deploy.MCP_BUILD


@pytest.mark.parametrize("where", ["account", "process"])
def test_file_worker_uid_is_reserved(where):
    accounts, processes = ([dc.WORKER_UID], []) if where == "account" else ([], [dc.WORKER_UID])
    with pytest.raises(ValueError):
        df_cleanup.check_reserved_uids(70000, 70010, accounts, processes)
    df_cleanup.check_reserved_uids(70000, 70010, [1000], [1000])


# ---- the formal check holds the profile to the 1.1/2.3 conditions --------------------------------------------------------
@pytest.fixture
def formal_repo(tmp_path):
    base = tmp_path / "repo" / df_baseline.BASE
    (base / "artifacts" / dc.BASELINE / "engine").mkdir(parents=True)
    (base / "artifacts" / dc.BASELINE / "engine" / "a.py").write_text("x\n")
    (base / "versions.json").write_text(json.dumps({dc.BASELINE: {"engine_path": dc.ENGINE_PATH,
                                                               "engine_commit": dc.ENGINE_COMMIT}}))
    (base / "host-readings").mkdir()
    config = tmp_path / "config.gz"
    with gzip.open(config, "wb") as f:
        f.write(b"CONFIG_SECCOMP_FILTER=y\n")
    pid_max = Path("/proc/sys/kernel/pid_max").read_text().strip()
    # the shape of the step-6 profile draft: version, kernel, config_sha256, approved_by_user, sources, required, readings
    profile = {"version": dc.BASELINE, "kernel": "k-test", "approved_by_user": "2026-11-06",
               "config_sha256": hashlib.sha256(b"CONFIG_SECCOMP_FILTER=y\n").hexdigest(), "sources": ["fixture"],
               "required": ["kernel.pid_max"],
               "readings": {"kernel.pid_max": {"path": "/proc/sys/kernel/pid_max", "value": pid_max}}}
    return tmp_path / "repo", base, config, profile, df_deploy.inventory(base / "artifacts" / dc.BASELINE / "engine")


def run_verify(formal_repo, **changes):
    repo, base, config, profile, snapshot = formal_repo
    (base / "host-readings" / f"{dc.BASELINE}.json").write_text(json.dumps({**profile, **changes}))
    calls = []
    out = df_baseline.verify(repo, snapshot, "k-test", lambda argv, **kw: calls.append(argv) or {"exit_code": 0},
                             variant=None, config_gz=config)
    return out, calls


def test_complete_profile_is_formal(formal_repo):
    out, calls = run_verify(formal_repo)
    assert out["formal"] and out["baseline"] == dc.BASELINE and not out["reasons"] and len(calls) == 1


@pytest.mark.parametrize("changes, reason", [
    ({"config_sha256": "0" * 64}, "kernel CONFIG differs"),
    ({"config_sha256": ""}, "kernel CONFIG differs"),
    ({"required": ["kernel.pid_max", "kernel.sysrq"]}, "required set differs"),
    ({"required": []}, "required set differs"),
    ({"version": "v3"}, "not a complete approved profile"),
    ({"sources": []}, "not a complete approved profile"),
    ({"approved_by_user": ""}, "not a complete approved profile"),
    ({"kernel": "other"}, "another kernel"),
    ({"readings": {"kernel.pid_max": {"path": "/proc/sys/kernel/pid_max", "value": "1"}}}, "differs"),
])
def test_incomplete_or_mismatched_profile_is_a_trial(formal_repo, changes, reason):
    out, calls = run_verify(formal_repo, **changes)
    assert not out["formal"] and out["baseline"] is None and not calls
    assert any(reason in r for r in out["reasons"]), out["reasons"]


# ---- evidence that cannot be read is a trial reason, never formal and never raised (review F2) ---------------------------
def raw_verify(formal_repo, profile_text=None, versions_text=None, profile_dir=False):
    repo, base, config, profile, snapshot = formal_repo
    target = base / "host-readings" / f"{dc.BASELINE}.json"
    if profile_dir:
        target.mkdir()
    else:
        target.write_text(profile_text if profile_text is not None else json.dumps(profile))
    if versions_text is not None:
        (base / "versions.json").write_text(versions_text)
    calls = []
    out = df_baseline.verify(repo, snapshot, "k-test", lambda argv, **kw: calls.append(argv) or {"exit_code": 0},
                             variant=None, config_gz=config)
    return out, calls


@pytest.mark.parametrize("case, reason", [
    ("missing-sysctl", "unreadable"),
    ("profile-is-a-directory", "host-readings profile unreadable or not JSON"),
    ("profile-not-json", "host-readings profile unreadable or not JSON"),
    ("profile-a-list", "host-readings profile is not a JSON object"),
    ("readings-a-list", "readings are not an object"),
    ("reading-a-string", "readings are not an object"),
    ("required-a-number", "required set differs"),
    ("path-a-number", "is not a /proc/sys value"),
    ("versions-not-json", "registered versions file unreadable or not JSON"),
])
def test_unreadable_or_malformed_evidence_is_a_trial(formal_repo, case, reason):
    profile = formal_repo[3]
    missing = {"kernel.nb_decoy_missing": {"path": "/proc/sys/kernel/nb-decoy-missing", "value": "1"}}
    texts = {
        "missing-sysctl": json.dumps({**profile, "readings": missing, "required": list(missing)}),
        "profile-not-json": "{not json",
        "profile-a-list": json.dumps([profile]),
        "readings-a-list": json.dumps({**profile, "readings": [1, 2]}),
        "reading-a-string": json.dumps({**profile, "readings": {"kernel.pid_max": "4194304"}}),
        "required-a-number": json.dumps({**profile, "required": 7}),
        "path-a-number": json.dumps({**profile, "readings": {"kernel.pid_max": {"path": 7, "value": "1"}}}),
    }
    out, calls = raw_verify(formal_repo, profile_text=texts.get(case), profile_dir=case == "profile-is-a-directory",
                            versions_text="{broken" if case == "versions-not-json" else None)
    assert not out["formal"] and out["baseline"] is None and not calls
    assert any(reason in r for r in out["reasons"]), out["reasons"]
