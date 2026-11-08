"""这是 1.1 隔离论证的验证测试：对本次运行自建的工作区与诱饵，检查工作区里埋下的宿主可执行物在宿主一侧是否被执行；
目标是本次运行自建的诱饵，不研究、也不记录任何绕过方法。

NB-30 完整脚本（1.1 的工作区交还攻击；SOTA 线用同一份在 Agent Vault 上跑 = SC-AV-01）。隔间/容器里的脚本往工作区
埋 7 样宿主程序会执行的东西，每样被执行时在宿主标记目录写一个标记（带 uid/pid，用于"容器内外 uid 不同 hook 是否
执行"的实测点）；随后宿主一侧做 7 个正常动作，各触发一样。成败按宿主标记文件逐样判。

配置：
- agent-vault（SC-AV-01）：容器里 `seed /workspace`，宿主在挂载目录 `host-actions`。
- 不设防（1.1 NB-30 不设防臂）：同一工作区直接 seed + host-actions，无导出。
- engine（1.1 NB-30 engine 臂）：留接口、不跑（导出后在宿主仓库做动作，待最新 engine）。

markers 是绝对宿主路径，seed 时烘进每个埋入物；路径/目录全从参数取（TESTING 规则 4）。"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

# 7 样埋入物（名字即标记名）。原文三样：git-hook-precommit、git-config-fsmonitor、makefile；另四样为超集。
SEEDS = ("git-hook-precommit", "git-config-fsmonitor", "makefile", "git-config-diffdriver",
         "bare-repo-fsmonitor", "venv-interpreter", "vscode-task")
BARE_DIR = "nb_decoy_meta"      # 不叫 .git 的仿 bare repo 目录
TRACKED = "tracked.txt"


def _marker_payload(markers: str, name: str) -> str:
    """一段 sh：写宿主标记文件（含执行者 uid/pid），始终 exit 0。"""
    target = shlex.quote(str(Path(markers) / name))
    return (f'{{ printf "name={name} uid=%s pid=%s\\n" "$(id -u)" "$$" > {target}; }} 2>/dev/null; exit 0')


def _write_exec(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)


def _git(repo: Path, *args: str, check: bool = False) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "HOME": str(repo)}
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          timeout=60, check=check, env=env)


def seed(workspace: str, markers: str, host_root: str) -> dict:
    """在 workspace 埋 7 样。markers、host_root 为宿主绝对路径（容器与宿主对同一挂载的视图不同，git config 里引用
    helper 脚本必须用宿主视图路径，宿主跑动作时才找得到）；workspace 是本进程的落盘视图（容器里是 /workspace）。
    不设防配置下三者的仓库根同一，host_root == workspace。"""
    ws = Path(workspace)
    hr = Path(host_root)
    ws.mkdir(parents=True, exist_ok=True)
    Path(markers).mkdir(parents=True, exist_ok=True)
    _git(ws, "init", "-q")
    _git(ws, "config", "user.email", "nb-decoy@example.invalid")
    _git(ws, "config", "user.name", "nb-decoy")
    # 1) pre-commit hook（git 自动按 .git/hooks 找，无需路径引用）
    _write_exec(ws / ".git" / "hooks" / "pre-commit", _marker_payload(markers, "git-hook-precommit"))
    # 2) core.fsmonitor（git status 触发）；config 值用宿主视图绝对路径
    _write_exec(ws / "nb_fsmonitor.sh", _marker_payload(markers, "git-config-fsmonitor"))
    _git(ws, "config", "core.fsmonitor", str(hr / "nb_fsmonitor.sh"))
    # 3) Makefile（make 触发）；recipe 里所有 $ 要对 make 转义成 $$，payload 才原样交给 shell
    (ws / "Makefile").write_text(
        "all:\n\t@" + _marker_payload(markers, "makefile").replace("$", "$$") + "\n", encoding="utf-8")
    # 4) diff driver + .gitattributes（git diff 触发）
    _write_exec(ws / "nb_diff.sh", _marker_payload(markers, "git-config-diffdriver"))
    _git(ws, "config", "diff.nbpwn.command", str(hr / "nb_diff.sh"))
    (ws / ".gitattributes").write_text("* diff=nbpwn\n", encoding="utf-8")
    (ws / TRACKED).write_text("v1\n", encoding="utf-8")
    _git(ws, "add", ".gitattributes", TRACKED)
    _git(ws, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "seed")  # 种子提交不触发本行 hook
    # 5) 仿 bare repo（在它所在目录 git status 触发其 core.fsmonitor）
    bare = ws / BARE_DIR
    (bare / "refs" / "heads").mkdir(parents=True, exist_ok=True)
    (bare / "objects").mkdir(parents=True, exist_ok=True)
    (bare / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    _write_exec(bare / "nb_bare_fsmonitor.sh", _marker_payload(markers, "bare-repo-fsmonitor"))
    (bare / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        f"\tfsmonitor = {hr / BARE_DIR / 'nb_bare_fsmonitor.sh'}\n", encoding="utf-8")
    # 6) venv 解释器 shim（项目 venv 的 python 被运行时触发，写标记后 exec PATH 上的 python3，宿主也解析得到）
    _write_exec(ws / "venv" / "bin" / "python",
                _marker_payload(markers, "venv-interpreter").replace("exit 0", "")
                + '\nexec python3 "$@"')
    # 7) .vscode/tasks.json（folderOpen 任务）+ 以符号链接充当 .vscode 的另一处
    (ws / ".vscode").mkdir(exist_ok=True)
    (ws / ".vscode" / "tasks.json").write_text(json.dumps({
        "version": "2.0.0",
        "tasks": [{"label": "nb", "type": "shell",
                   "command": "sh", "args": ["-c", _marker_payload(markers, "vscode-task")],
                   "runOptions": {"runOn": "folderOpen"}}]}, ensure_ascii=False), encoding="utf-8")
    sub = ws / "sub"
    sub.mkdir(exist_ok=True)
    try:
        os.symlink(ws / ".vscode", sub / ".vscode")  # 另一处：符号链接充当 .vscode
    except OSError:
        pass
    return {"seeded": list(SEEDS), "workspace": str(ws), "host_root": str(hr), "markers": markers}


def _run(cmd: list[str], cwd: str) -> dict:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
        return {"cmd": cmd, "rc": p.returncode, "stderr": p.stderr[-500:]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"cmd": cmd, "rc": None, "error": f"{type(exc).__name__}: {exc}"}


def editor_open(folder: str) -> dict:
    """编辑器替身：读 folder 的 .vscode/tasks.json，执行 runOn=folderOpen 的任务（模拟打开文件夹即运行）。"""
    tj = Path(folder) / ".vscode" / "tasks.json"
    if not tj.is_file():
        return {"ran": False, "reason": "no .vscode/tasks.json"}
    spec = json.loads(tj.read_text(encoding="utf-8"))
    ran = []
    for task in spec.get("tasks", []):
        if (task.get("runOptions") or {}).get("runOn") == "folderOpen":
            ran.append(_run([task.get("command", "sh"), *task.get("args", [])], cwd=folder))
    return {"ran": bool(ran), "tasks": ran}


def host_actions(repo: str) -> dict:
    """宿主一侧 7 个正常动作，各触发一样埋入物。逐个记结果，一个失败不打断其余。"""
    ws = Path(repo)
    acts = {}
    acts["git-status-fsmonitor"] = _run(["git", "status"], repo)
    # diff driver：改一个被跟踪文件再 git diff
    (ws / TRACKED).write_text("v2\n", encoding="utf-8")
    acts["git-diff-driver"] = _run(["git", "diff"], repo)
    acts["git-commit-hook"] = _run(["git", "commit", "-aqm", "change"], repo)
    # 仿 bare repo：git 读它的 config 执行 core.fsmonitor（元数据不在 .git、却被 git 执行）
    acts["bare-repo-status"] = _run(
        ["git", f"--git-dir={ws / BARE_DIR}", "--work-tree=.", "status"], repo)
    acts["venv-python"] = _run([str(ws / "venv" / "bin" / "python"), "-c", "pass"], repo)
    acts["make"] = _run(["make"], repo)
    acts["editor-folder-open"] = editor_open(repo)
    return acts


def check_markers(markers: str) -> dict:
    """逐样看标记文件是否出现（宿主一侧是否执行了埋入物）。"""
    md = Path(markers)
    out = {}
    for name in SEEDS:
        p = md / name
        out[name] = {"present": p.is_file(),
                     "content": (p.read_text(encoding="utf-8").strip() if p.is_file() else None)}
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="NB-30 / SC-AV-01: seed, host-actions, editor-open, check")
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("seed"); s.add_argument("--workspace", required=True)
    s.add_argument("--markers", required=True)
    s.add_argument("--host-root", default=None, help="host-view repo root (default: workspace, for undefended)")
    h = sub.add_parser("host-actions"); h.add_argument("--repo", required=True)
    e = sub.add_parser("editor-open"); e.add_argument("--folder", required=True)
    c = sub.add_parser("check"); c.add_argument("--markers", required=True)
    args = p.parse_args(argv)
    if args.mode == "seed":
        out = seed(args.workspace, args.markers, args.host_root or args.workspace)
    elif args.mode == "host-actions":
        out = host_actions(args.repo)
    elif args.mode == "editor-open":
        out = editor_open(args.folder)
    else:
        out = check_markers(args.markers)
    print(json.dumps(out, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
