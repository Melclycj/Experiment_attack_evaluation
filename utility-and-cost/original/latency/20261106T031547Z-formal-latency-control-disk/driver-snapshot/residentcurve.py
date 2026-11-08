"""How a resident Claude Code's memory evolves after start (protocol.md 11: the "second rise" that sets the resident
state's minimum wait). One unit of an adapter; unit PSS every 5 s for the given seconds. Not a measurement.

    python3 -m driver.residentcurve bare 240
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from . import client, objects

EXP = Path(__file__).resolve().parents[1]


def main() -> None:
    name, seconds = sys.argv[1], float(sys.argv[2])
    run_dir = EXP / "runs" / f"{time.strftime('%Y%m%dT%H%M%S')}-curve-{name}"
    run_dir.mkdir(parents=True)
    agent = client.Agent(run_dir)
    obj = objects.ADAPTERS[name](lambda: agent, objects.api_key())
    obj.run_dir = run_dir
    curve = []
    try:
        obj.prepare()
        obj.start_shared()
        obj.create_units(1)
        obj.set_state("idle")
        time.sleep(5)
        obj.set_state("resident")
        t0 = time.time()
        while time.time() - t0 < seconds:
            g = agent.call("reading", groups=obj.groups())["groups"]["unit"]
            curve.append((round(time.time() - t0), round(g["pss_mib"], 1), g["procs"]))
            time.sleep(5)
    finally:   # each step runs even if the one before fails, as in smoke.py
        try:
            obj.destroy_units()
        finally:
            try:
                obj.stop_shared()
            finally:
                agent.close()
    (run_dir / "curve.json").write_text(json.dumps(curve), encoding="utf-8")
    print(json.dumps(curve))


if __name__ == "__main__":
    main()
