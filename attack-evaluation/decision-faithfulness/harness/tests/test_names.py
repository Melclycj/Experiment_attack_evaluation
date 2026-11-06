"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

No linter is installed on this machine: a coarse stand-in. Every module imports, and every name a module reads is
bound somewhere in that module or is a builtin (catches misspelt names in code the other tests do not reach).
"""
from __future__ import annotations

import ast
import builtins
import importlib

import pytest

from conftest import HARNESS, SCRIPTS

MODULES = sorted(p for p in list(HARNESS.glob("*.py")) + list(SCRIPTS.glob("*.py")))


def bound(tree: ast.AST) -> set[str]:
    names = set(dir(builtins)) | {"__file__", "__name__", "__doc__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_every_read_name_is_bound(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    known = bound(tree)
    missing = sorted({n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                      and n.id not in known})
    assert not missing, (path.name, missing)


@pytest.mark.parametrize("name", sorted(p.stem for p in HARNESS.glob("*.py")))
def test_harness_module_imports(name):
    importlib.import_module(name)
