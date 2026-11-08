"""Component smoke test of one adapter on the server: shared parts, N units, idle, resident, destroy; print the
readings that the memory column would use and each unit's prompt evidence. Not a measurement.

    python3 -m driver.smoke bare 2
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from . import client, objects

EXP = Path(__file__).resolve().parents[1]


def main() -> None:
    name, n = sys.argv[1], int(sys.argv[2])
    run_dir = EXP / "runs" / f"{time.strftime('%Y%m%dT%H%M%S')}-smoke-{name}"
    run_dir.mkdir(parents=True)
    agent = client.Agent(run_dir)
    obj = objects.ADAPTERS[name](lambda: agent, objects.api_key())
    obj.run_dir = run_dir
    agent.call("groups", groups={**obj.groups(), "harness": objects.HARNESS})
    out = {}
    try:
        obj.prepare()
        obj.start_shared()
        time.sleep(5)
        t0 = time.time()
        obj.create_units(n)
        obj.set_state("idle")
        out["build_and_idle_s"] = round(time.time() - t0, 1)
        time.sleep(15)
        out["idle"] = snapshot(agent, obj)
        obj.set_state("resident")
        time.sleep(45)
        out["resident"] = snapshot(agent, obj)
        out["prompt"] = obj.prompt_evidence()
        out["notes"] = obj.rep_notes()
    finally:
        try:
            obj.destroy_units()
        finally:
            try:
                obj.stop_shared()
                time.sleep(5)
                out["after_destroy_residue"] = obj.residue()
            finally:
                try:
                    obj.teardown()      # an engine deployment holds the model key in its credential store
                finally:
                    agent.close()
    print(json.dumps(out, indent=1, ensure_ascii=False))


def snapshot(agent: client.Agent, obj) -> dict:
    row = agent.latest() or {}
    return {"dead_units": obj.alive(), "used_mib": round(row.get("used_mib", 0), 1), "groups": row.get("groups")}


if __name__ == "__main__":
    main()
