"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from pathlib import Path
import argparse
import faulthandler
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description="Unit tests only; never starts engine, attacks, mounts or network listeners")
parser.add_argument("--temp-root", type=Path, help="existing writable directory for disposable test fixtures")
args = parser.parse_args()
if args.temp_root is not None:
    if not args.temp_root.is_dir():
        parser.error("--temp-root must exist")
    tempfile.tempdir = str(args.temp_root.resolve())
faulthandler.dump_traceback_later(60, exit=True)
sys.path[:0] = [str(HERE.parent), str(HERE.parent / "cell"), str(HERE)]
suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py")
result = unittest.TextTestRunner(verbosity=2).run(suite)
faulthandler.cancel_dump_traceback_later()
raise SystemExit(0 if result.wasSuccessful() else 1)
