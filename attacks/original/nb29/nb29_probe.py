"""NB-29 档 2 轻探针（用户 2026-11-06）。只在 WSL 上、以 root 跑；gated：开跑前问用户、用户"开始"才跑。

坐实的只有 engine 代码之外那层——WSL binfmt_misc 互操作。做法（方法定稿见 ../tests.md §6）：
  · engine-like 隔间臂：`unshare -m` + `chroot` 到一个仿隔间承重性质的根（新 tmpfs、无 /init、无 /run/WSL），在里面 exec MZ 文件 → 预期 binfmt 无 F 标志 → 当前根找 /init → ENOENT → 起不了 Windows 进程、不写标记（挡住层①②）。
  · 不设防臂：在正常 WSL 根（/init、/run/WSL 都在）里 exec 同一个 MZ 文件 → 预期起 Windows 进程、写宿主标记（证明攻击目标真实可达，规则 3）。
  · PC-EXEC：同一个仿根里 exec 一个普通静态 Linux 程序 → 预期成功（exec 本身可用）。
层③（seccomp 拒 AF_VSOCK）不在探针里，读 policy.c 作结构论证。
红线：MZ 真起 Windows 进程、写出标记 = 真逃逸没挡住，照实报（规则 9），不得抹成无效。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from nb_common import DECOY, HOST_INIT, WSL_RUN_DIR, WSLINTEROP, run_name, utc

ENOENT = 2


def host_preconditions() -> dict:
    """只读记录 NB-29 的判决前提（tests.md §6.1）。"""
    try:
        interop = Path(WSLINTEROP).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        interop = f"(unreadable: {exc})"
    flags = next((ln.split("flags:", 1)[1].strip() for ln in interop.splitlines()
                  if ln.startswith("flags:")), None)
    return {"wslinterop": interop, "flags": flags, "no_F_flag": flags is not None and "F" not in flags,
            "host_init_exists": Path(HOST_INIT).exists(),
            "run_wsl_exists": Path(WSL_RUN_DIR).exists(),
            "run_wsl_entries": sorted(p.name for p in Path(WSL_RUN_DIR).iterdir()) if Path(WSL_RUN_DIR).is_dir() else []}


def build_cellroot(base: Path, mz: Path, pcexec: Path) -> Path:
    """仿隔间承重性质的根：只放 MZ 与 PC-EXEC（都应是静态、无需 chroot 内有 libs），不放 /init、不放 /run/WSL。"""
    cellroot = base / "cellroot"
    cellroot.mkdir(mode=0o755)
    shutil.copyfile(mz, cellroot / "nb29.mz")
    os.chmod(cellroot / "nb29.mz", 0o755)
    shutil.copyfile(pcexec, cellroot / "pcexec")
    os.chmod(cellroot / "pcexec", 0o755)
    assert not (cellroot / "init").exists(), "cellroot must not contain /init"
    assert not (cellroot / "run" / "WSL").exists(), "cellroot must not contain /run/WSL"
    return cellroot


def _run(argv: list[str], timeout: int = 30) -> dict:
    p = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
    return {"argv": [str(a) for a in argv], "exit": p.returncode, "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:]}


def arm_undefended(mz: Path, marker: Path, win_marker_arg: str) -> dict:
    """正常 WSL 根里 exec MZ；预期起 Windows 进程、写标记。"""
    marker.unlink(missing_ok=True)
    res = _run([str(mz), win_marker_arg])
    res["marker_present"] = marker.exists()
    return res


def arm_cell(cellroot: Path, marker: Path, win_marker_arg: str) -> dict:
    """unshare -m + chroot 仿根里 exec MZ；预期 ENOENT（/init 不在仿根）、不写标记。"""
    marker.unlink(missing_ok=True)
    res = _run(["unshare", "--mount", "--fork", "chroot", str(cellroot), "/nb29.mz", win_marker_arg])
    res["marker_present"] = marker.exists()
    # chroot 执行 /nb29.mz 失败时，退出码非 0、stderr 常含 "No such file or directory"（binfmt 找不到 /init）
    res["looks_enoent"] = res["exit"] != 0 and ("No such file or directory" in res["stderr"] or "ENOENT" in res["stderr"])
    return res


def arm_pcexec(cellroot: Path) -> dict:
    """同一个仿根里 exec 普通静态程序；预期成功。"""
    return _run(["unshare", "--mount", "--fork", "chroot", str(cellroot), "/pcexec"])


def judge(pre: dict, undef: dict, cell: dict, pc: dict) -> dict:
    """按 tests.md §6：ENOENT+无标记=挡住；有标记=成功（红线）；否则无效。"""
    verdict: dict = {}
    # 不设防臂：攻击目标可达的前提
    verdict["undefended_reachable"] = undef["marker_present"]
    # PC-EXEC：exec 本身可用
    verdict["pc_exec_ok"] = pc["exit"] == 0
    # 隔间臂
    if cell["marker_present"]:
        verdict["cell"] = "succeeded"            # 红线：真逃逸没挡住，照实报（规则 9）
        verdict["note"] = "MARKER WRITTEN IN CELL ARM — escape NOT blocked; report per rule 9"
    elif cell["looks_enoent"]:
        verdict["cell"] = "blocked"              # 层① ENOENT：/init 不在仿根
        verdict["note"] = "blocked at layer 1 (ENOENT: /init not in cell-like root)"
    else:
        verdict["cell"] = "invalid"              # 没标记、又不是 ENOENT：先查实际机制（规则 4）
        verdict["note"] = "no marker but exit is not ENOENT — investigate before counting as blocked"
    # 有效：不设防可达 + PC-EXEC ok 才算这对结果有效
    verdict["valid"] = verdict["undefended_reachable"] and verdict["pc_exec_ok"]
    return verdict


def main() -> int:
    ap = __import__("argparse").ArgumentParser(description="NB-29 档 2 轻探针（WSL, root）")
    ap.add_argument("--mz", type=Path, required=True, help="nb29.mz（mingw 编的 Windows PE）")
    ap.add_argument("--pcexec", type=Path, required=True, help="静态 Linux 小程序（PC-EXEC）")
    ap.add_argument("--run-dir", type=Path, required=True, help="结果留底目录（其下按 run 名建子目录）")
    ap.add_argument("--marker", type=Path, required=True,
                    help="宿主侧标记文件的 WSL 可见路径，如 /mnt/c/Users/Public/nb-decoy-nb29-marker")
    ap.add_argument("--win-marker", required=True, help="同一标记的 Windows 路径，传给 MZ 作 argv[1]")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("需以 root 跑（unshare -m + chroot）", file=sys.stderr)
        return 2

    nonce = uuid.uuid4().hex[:16]
    out = args.run_dir / run_name("nb29-probe")
    out.mkdir(parents=True)
    base = out / (DECOY + "cell")
    base.mkdir(mode=0o755)

    pre = host_preconditions()
    cellroot = build_cellroot(base, args.mz, args.pcexec)
    undef = arm_undefended(args.mz, args.marker, args.win_marker)
    cell = arm_cell(cellroot, args.marker, args.win_marker)
    pc = arm_pcexec(cellroot)
    verdict = judge(pre, undef, cell, pc)

    record = {"attack": "NB-29", "level": "试跑（档 2 探针）", "started_at_utc": utc(), "nonce": nonce,
              "preconditions": pre, "arms": {"undefended": undef, "cell": cell, "pc_exec": pc},
              "verdict": verdict,
              "layer3_note": "seccomp 拒 AF_VSOCK（层③）不在本探针，结构论证读 a9eff999:native/sandbox/policy.c",
              "consumer": "第 3 章 WSL 专项：3.2 特权表 WSL 行、3.5 Components、3.7 Mediation、A.15 第 10 件"}
    (out / "result.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 清理：删仿根与标记（统一清理顺序）
    args.marker.unlink(missing_ok=True)
    shutil.rmtree(base, ignore_errors=True)
    print(json.dumps({"verdict": verdict, "result": str(out / "result.json")}, ensure_ascii=False, indent=2))
    return 0 if verdict["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
