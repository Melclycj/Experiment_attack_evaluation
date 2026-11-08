"""Mechanical reconcile checks for the uid-binding fan-out, and the five-column table extractor.

Run with Python 3 from any working directory. Inputs: the spine files 02-conditions-and-decomposition.md
and 04-evidence-registry.md, every route file and preservation file under work/groups/. No file is
modified unless --table-out is given, in which case only that one output file is written. Exit 1 means a
hard check failed. This is the mechanical half of PLAN §Convergence; the judgement half is reconcile.md.

Checks (PLAN §Convergence, table "Reconcile reads"):
  1. route ledger (02 §6) <-> route files: exactly one file per ledger route and one ledger route per file;
     the file's group and violated-condition IDs agree with the ledger row;
  2. condition x group matrix (02 §8): every cell lists routes or says "no route"; listed routes exist;
  3. transition partition: 02 §7 group cut == preservation rows per group; every T- of 01's inventory
     cited in 02 §7 is owned once; every X- exclusion of 02 §7 is listed; every owned transition is cited
     by >= 1 route file;
  4. headers: four blob ids, status ready-for-reconcile, disposition one of four, stops/violates filled;
  5. vocabulary (PLAN Context (2)): no unqualified coverage words, no rate wording, in any route or
     preservation file;
  6. evidence IDs cited by route files exist in 04; proposed-evidence rows are collected for the append;
  7. no route marked "supported under stated premises" traverses a transition its own group's
     conclusion lines list under "does not preserve";
  8. counts: dispositions a/b/c/d; preservation results per group;
  9. (R3 F-01) the stops field equals section 3's first sentence or is its opening phrase (template: one phrase);
 10. (R3 F-05) every 'EV-nn [tag]' pair in route, preservation and convergence files matches 04;
 11. (R3 F-10) the vocabulary scan also covers convergence/ (allowing 'complete relative to M') and
     the group change-request files;
 12. (R3 F-02) explicit section-6 citations of C1-C4 and obligations #1-#6 are counted (--mapping lists them).
Table: --table-out <path> writes the five-column table (route ID, section-1 sentence, violates, stops,
disposition) extracted from front matter and section 1, nothing hand-written.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPINE = ROOT / "spine"
GROUPS = ROOT / "groups"
GROUP_ORDER = ["G1", "G2", "G3", "G4", "G5", "GX"]
BLOBS = {
    "model_blob": "7345e9c5d8face07",
    "decomposition_blob": "558f035982198c7c",
    "invariant_blob": "af8662ca14b83598",
    "registry_blob": "b868512116d812f0",
}
# the spine versions of 2026-10-15/16; a re-read file copies all four, an untouched file keeps the gate set
BLOBS_CURRENT = {'model_blob': '9efb243354a4e9d6', 'decomposition_blob': '31ddfc5daba58f13', 'invariant_blob': '6868389a2182c161', 'registry_blob': 'f36170e09dd4c2a9'}
# 04 v5 (2026-10-16, kernel reading EV-142..146, pure appends): a file re-run after it copies this set
BLOBS_V5 = {**BLOBS_CURRENT, 'registry_blob': '52e0625ffeebf23a'}
# second design freeze 2026-10-18 (01 v9, 02 v7; 03 v4 and 04 v5 unchanged in meaning): a file re-run or re-worded after it copies this set
BLOBS_FREEZE2 = {'model_blob': '1461a0f9feb23817', 'decomposition_blob': '8627a717b631d01b', 'invariant_blob': '6868389a2182c161', 'registry_blob': '52e0625ffeebf23a'}
# third design freeze 2026-10-18 (agent-facing grant_ref removed; 01 v10): files re-run or re-worded after it
BLOBS_FREEZE3 = {**BLOBS_FREEZE2, 'model_blob': 'd27d65d7874bbf6c'}
# follow-up step 4 (2026-10-19): 01 v10, 02 v9, 03 v5, 04 v7 (engine-build evidence appended)
BLOBS_STEP4 = {'model_blob': 'd27d65d7874bbf6c', 'decomposition_blob': '5d2a0b9438f37302', 'invariant_blob': 'ae58d7db31c95c82', 'registry_blob': '97b869a738a79b0e'}
BLOBS_STEP4B = {**BLOBS_STEP4, 'registry_blob': '3468e10efd7f8e06'}  # 04 v8: step-4 proposals registered
BLOBS_STEP4C = {**BLOBS_STEP4, 'registry_blob': '751aa7d69983c406'}  # 04 v9: C-side body parse removed (engine 7b4ab727)
BLOBS_STEP4D = {**BLOBS_STEP4C, 'decomposition_blob': 'eceee4b4c7426e3a'}  # 02 v10 wording + 04 v9
BLOBS_REV5 = {'model_blob': '8e5d9e5d21330b6a', 'decomposition_blob': 'eceee4b4c7426e3a', 'invariant_blob': 'ae58d7db31c95c82', 'registry_blob': '4677f3ac0fa71744'}  # fifth design revision: 01 v11, 04 v10
BLOBS_REV5B = {**BLOBS_REV5, 'registry_blob': 'bae8d231316b294f'}  # 04 v11: engine fixes 9981dd7b
BLOBS_REV5C = {**BLOBS_REV5, 'registry_blob': '046b0449a22e687c'}  # 04 v12: extra evidence, engine b262e80e
HEADER_SETS = {"gate": BLOBS, "current": BLOBS_CURRENT, "current-v5": BLOBS_V5, "freeze2": BLOBS_FREEZE2, "freeze3": BLOBS_FREEZE3, "step4": BLOBS_STEP4, "step4b": BLOBS_STEP4B, "step4c": BLOBS_STEP4C, "step4d": BLOBS_STEP4D, "rev5": BLOBS_REV5, "rev5b": BLOBS_REV5B, "rev5c": BLOBS_REV5C}


def header_set(fm: dict) -> str:
    for name, s in HEADER_SETS.items():
        if all(fm.get(k) == v for k, v in s.items()):
            return name
    return ""
DISPOSITIONS = [
    "supported under stated premises",
    "conditional on unbuilt requirements",
    "open",
    "declared out of scope",
]
FORBIDDEN = re.compile(
    r"\b([cC]losure|[cC]losed|[cC]omplete(?:ly|ness)?|[eE]xhaustive(?:ly)?|[pP]roven|[fF]ixed-point)\b"
)
RATE = re.compile(r"\b\d+(?:\.\d+)?\s?%|\bsuccess[- ]rate\b|\bpercent(?:age)?\b", re.I)

hard: list[str] = []
soft: list[str] = []
header_counts: dict[str, int] = {}


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def front_matter(text: str) -> dict[str, str]:
    m = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    fm: dict[str, str] = {}
    if m:
        for line in m.group(1).splitlines():
            mm = re.match(r"^\s*([A-Za-z_]+):\s*(.*?)\s*(#.*)?$", line)
            if mm:
                fm[mm.group(1)] = mm.group(2).strip().strip('"')
    return fm


def section(text: str, n: int) -> str:
    m = re.search(rf"^## {n} .*?$(.*?)(?=^## |\Z)", text, re.S | re.M)
    return m.group(1).strip() if m else ""


def cids(text: str) -> set[str]:
    out = set(re.findall(r"\bC-\d{2}\b", text))
    for m in re.finditer(r"\bC-(\d{2})\s?[–…]\s?(?:C-)?(\d{2})\b", text):
        out.update(f"C-{i:02d}" for i in range(int(m[1]), int(m[2]) + 1))
    return out


# 02 §7: T-66 is a boundary disturbance row and T-67 tests configured premise departures; neither is a
# transition the normal invariant admits, so their branch-qualified "does not preserve" results are
# premise departures, not a defence failing. A route that traverses them may still be "supported under
# stated premises" only if its section 5 names the premise whose departure the branch is (check 7).
PREMISE_ROWS = {"T-66", "T-67"}


def tids(text: str) -> set[str]:
    out = set(re.findall(r"\bT-\d{2}\b", text))
    for m in re.finditer(r"\bT-(\d{2})\s?[–…]\s?(?:T-)?(\d{2})\b", text):
        out.update(f"T-{i:02d}" for i in range(int(m[1]), int(m[2]) + 1))
    return out


# ---------- 02: ledger, group cut, matrix ----------
b = read(SPINE / "02-conditions-and-decomposition.md")
led_sec = re.search(r"^## 6 Route ledger.*?(?=^## 7 )", b, re.S | re.M).group(0)
ledger: dict[str, dict[str, str]] = {}
for line in led_sec.splitlines():
    m = re.match(r"^\|\s*(R-G[1-5X]-\d{2})\s*\|(.*)$", line)
    if m:
        cells = [c.strip() for c in m.group(2).strip().strip("|").split("|")]
        if len(cells) >= 5:
            ledger[m.group(1)] = {
                "sentence": cells[0],
                "violates": cells[2],
                "group": cells[3],
                "cross": cells[4],
            }
cut_sec = re.search(r"^## 7 Group cut.*?(?=^## 8 )", b, re.S | re.M).group(0)
group_cut: dict[str, set[str]] = {}
for line in cut_sec.splitlines():
    m = re.match(r"^\|\s*(G[1-5])\b[^|]*\|\s*([^|]*)\|", line)
    if m:
        group_cut[m.group(1)] = tids(m.group(2))
cut_exclusions = set(re.findall(r"^\|\s*(X-\d{2})\s*\|", cut_sec, re.M))
mat_sec = re.search(r"^## 8 Condition.*?(?=^\[R1\]|\Z)", b, re.S | re.M).group(0)
matrix_cells = 0
for line in mat_sec.splitlines():
    m = re.match(r"^\|\s*(C-\d{2})\s*\|(.*)$", line)
    if not m:
        continue
    cond = m.group(1)
    cells = [c.strip() for c in m.group(2).strip().strip("|").split("|")]
    for g, cell in zip(GROUP_ORDER, cells):
        matrix_cells += 1
        refs = re.findall(r"\b(?:G[1-5]|GX)-\d{2}(?:,\d{2})*", cell)
        if not refs and not cell.lower().startswith("no route"):
            hard.append(f"02 §8 cell {cond} x {g} neither lists routes nor says 'no route': {cell[:60]!r}")
        for ref in refs:
            base = ref.split("-")[0]
            for num in ref.split("-")[1].split(","):
                rid = f"R-{base}-{num}"
                if rid not in ledger:
                    hard.append(f"02 §8 cell {cond} x {g} cites {rid}, not in the ledger")
                elif cond not in cids(ledger[rid]["violates"]):
                    soft.append(f"02 §8 cell {cond} x {g} lists {rid} whose ledger row violates {ledger[rid]['violates']!r}")

# ---------- 04: evidence IDs ----------
d = read(SPINE / "04-evidence-registry.md")
registry_ids = set(re.findall(r"^\|\s*(EV-\d{2,3})\s*\|", d, re.M))

# ---------- route files ----------
routes: dict[str, dict[str, object]] = {}
pres: dict[str, dict[str, object]] = {}
for gdir in sorted(GROUPS.iterdir()):
    if not gdir.is_dir():
        continue
    g = gdir.name.split("-")[0]
    for p in sorted(gdir.glob("*.md")):
        text = read(p)
        if p.name == "change-requests.md":
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for m in FORBIDDEN.finditer(line):
                hard.append(f"{g}/{p.name}:{i}: forbidden word {m.group(0)!r}")
            for m in RATE.finditer(line):
                hard.append(f"{g}/{p.name}:{i}: rate wording {m.group(0)!r}")
        fm = front_matter(text)
        if fm.get("status") != "ready-for-reconcile":
            hard.append(f"{g}/{p.name}: status {fm.get('status')!r}")
        hs = header_set(fm)
        if not hs:
            hard.append(f"{g}/{p.name}: header ids match neither the gate set nor the current set")
        header_counts[hs] = header_counts.get(hs, 0) + 1
        if p.name == "preservation.md":
            rows = set(re.findall(r"^\|\s*(T-\d{2})\b", text, re.M))
            concl = re.search(r"^## Conclusion lines.*", text, re.S | re.M)
            ctext = concl.group(0) if concl else ""
            dnp = re.search(r"^- does not preserve:(.*)$", ctext, re.M)
            pres[g] = {
                "rows": rows,
                "does_not_preserve": tids(dnp.group(1)) if dnp and "none" not in dnp.group(1)[:12] else set(),
                "conclusion": ctext.strip(),
                "text": text,
            }
            if not concl:
                hard.append(f"{g}/preservation.md: no conclusion lines")
            continue
        if not p.name.startswith("R-"):
            soft.append(f"{g}/{p.name}: unexpected file")
            continue
        rid = fm.get("route_id", "")
        if rid + ".md" != p.name:
            hard.append(f"{g}/{p.name}: route_id {rid!r} != file name")
        disp = fm.get("disposition", "")
        if disp not in DISPOSITIONS:
            hard.append(f"{g}/{p.name}: disposition {disp!r}")
        if not fm.get("stops") or not fm.get("violates"):
            hard.append(f"{g}/{p.name}: stops or violates empty")
        s1 = re.sub(r"\s+", " ", section(text, 1))
        s2 = section(text, 2)
        s4 = section(text, 4)
        s6 = section(text, 6)
        ev = set(re.findall(r"\bEV-\d{2,3}\b", text))
        for e in sorted(ev - registry_ids):
            hard.append(f"{g}/{p.name}: cites {e}, not in 04")
        proposed: list[str] = []
        pm = re.search(r"\*\*Proposed evidence[^\n]*\n(.*)", s4, re.S)
        if pm:
            prose: list[str] = []
            for line in pm.group(1).splitlines():
                line = line.strip()
                if not line:
                    if prose:
                        proposed.append("prose: " + " ".join(prose))
                        prose = []
                    continue
                if line.startswith("- "):
                    proposed.append(line[2:].strip())
                elif line.startswith("|"):
                    cells = [c.strip() for c in line.strip("|").split("|")]
                    if all(re.fullmatch(r"-+", c) for c in cells) or cells[0].lower() in ("evidence id", "tag", "—", "-") and len(cells) > 1 and cells[1].lower() in ("tag", "fact", "what it would show", "what it shows"):
                        continue
                    proposed.append(" | ".join(c for c in cells if c and c not in ("—", "-", "–")))
                else:
                    prose.append(line)
            if prose:
                proposed.append("prose: " + " ".join(prose))
        obligations: list[str] = []
        s6_lines = s6.splitlines()
        i = 0
        while i < len(s6_lines):
            if re.match(r"^- \*{0,2}Design obligations?", s6_lines[i]):
                block = [s6_lines[i]]
                i += 1
                while i < len(s6_lines) and not re.match(r"^- ", s6_lines[i]) and s6_lines[i].strip():
                    block.append(s6_lines[i])
                    i += 1
                obligations.append(re.sub(r"\s+", " ", " ".join(block)).strip())
                continue
            i += 1
        routes[rid] = {
            "group": fm.get("group", ""),
            "folder": g,
            "violates": fm.get("violates", ""),
            "stops": fm.get("stops", ""),
            "disposition": disp,
            "s1": s1,
            "transitions": tids(s2),
            "proposed": proposed,
            "obligations": obligations,
            "ev": ev,
            "s5": section(text, 5),
            "s3": section(text, 3),
            "s6": s6,
            "text": text,
        }

# ---------- check 1: ledger <-> files ----------
for rid, row in ledger.items():
    if rid not in routes:
        hard.append(f"ledger route {rid} has no route file")
        continue
    r = routes[rid]
    if r["group"] != row["group"]:
        hard.append(f"{rid}: file group {r['group']} != ledger group {row['group']}")
    if r["folder"] != row["group"]:
        hard.append(f"{rid}: lives in folder {r['folder']}, ledger group {row['group']}")
    if not cids(row["violates"]) <= cids(str(r["violates"])):
        hard.append(f"{rid}: file violates {r['violates']!r} lacks ledger's {row['violates']!r}")
for rid in routes:
    if rid not in ledger:
        hard.append(f"route file {rid} has no ledger row")

# ---------- check 3: partition ----------
owned: dict[str, list[str]] = {}
for g, ts in group_cut.items():
    for t in ts:
        owned.setdefault(t, []).append(g)
for t, gs in owned.items():
    if len(gs) != 1:
        hard.append(f"02 §7 assigns {t} to {gs}")
for g, ts in group_cut.items():
    rows = pres.get(g, {}).get("rows", set())
    if rows != ts:
        hard.append(f"{g}: preservation rows {sorted(rows - ts)} extra, {sorted(ts - rows)} missing vs 02 §7")
a = read(SPINE / "01-model-inventory.md")
inv_t = set(re.findall(r"^\|\s*(T-\d{2})\b", a, re.M))
inv_x = set(re.findall(r"\bX-\d{2}\b", a))
for t in sorted(inv_t - set(owned)):
    hard.append(f"01 transition {t} owned by no group in 02 §7")
for x in sorted(inv_x - cut_exclusions):
    soft.append(f"01 exclusion {x} not listed in 02 §7")
cited_t: set[str] = set()
for r in routes.values():
    cited_t |= r["transitions"]  # type: ignore[operator]
for rid, row in ledger.items():
    cited_t |= tids(row["cross"])
for t in sorted(set(owned) - cited_t):
    soft.append(f"transition {t} is cited by no route file (section 2) and no ledger row")

# ---------- check 7: supported vs does-not-preserve ----------
for rid, r in routes.items():
    if r["disposition"] == DISPOSITIONS[0]:
        g = str(r["group"])
        bad = r["transitions"] & pres.get(g, {}).get("does_not_preserve", set())  # type: ignore[operator]
        admitted_bad = bad - PREMISE_ROWS
        premise_bad = bad & PREMISE_ROWS
        if admitted_bad:
            hard.append(f"{rid} is 'supported under stated premises' but traverses {sorted(admitted_bad)} which {g} lists under 'does not preserve'")
        if premise_bad:
            s5 = str(r["s5"])
            if "Premises that must hold" not in s5 or not re.search(r"\bC1\b|\bC2\b|\bC3\b|exclusive", s5):
                hard.append(f"{rid} traverses the premise-departure row {sorted(premise_bad)} and its section 5 does not name the premise (C1 / C2 / C3 / exclusive pool)")
            else:
                soft.append(f"{rid} traverses {sorted(premise_bad)} (premise departure, 02 §7); supported only on the branches where its section-5 premises hold — judged in reconcile.md")


# ---------- check 9 (R3 F-01): stops field == first sentence of section 3 ----------
def _norm(s: str) -> str:
    s = re.sub(r"\s+", " ", s).strip().strip('"').rstrip(".").lower()
    return re.sub(r"[`*]", "", s)


def _first_sentence(s: str) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    m = re.match(r"(.+?[.!?])(\s|$)", s)
    return m.group(1) if m else s


for rid, r in routes.items():
    a = _norm(str(r["stops"]))
    b = _norm(_first_sentence(str(r["s3"])))
    if a != b and not b.startswith(a):
        hard.append(f"{rid}: stops field is neither section 3's first sentence nor its opening phrase")

# ---------- check 10 (R3 F-05): every 'EV-nn [tag]' pair in fan-out and convergence files matches 04 ----------
reg_tags = {}
for line in d.splitlines():
    m = re.match(r"^\|\s*(EV-\d{2,3})\s*\|\s*(\[[MRS]\])\s*\|", line)
    if m and m.group(1) not in reg_tags:
        reg_tags[m.group(1)] = m.group(2)
pair = re.compile(r"\b(EV-\d{2,3})\s+(\[[MRS]\])")
# engine-requirements.md moved to the design folder 2026-10-18 (user ruling); it stays in both scans
MOVED = [ROOT.parents[3] / "Design" / "sandbox-mediated-agent-execution" / "engine-requirements.md"]
scan_files = sorted(GROUPS.glob("*/*.md")) + sorted((ROOT / "convergence").glob("*.md")) + MOVED
for p in scan_files:
    if p.name == "registry-appends.md":
        continue  # the draft records the pre-v4 state by design
    for i, line in enumerate(read(p).splitlines(), 1):
        for m in pair.finditer(line):
            if m.group(1) in reg_tags and reg_tags[m.group(1)] != m.group(2):
                hard.append(f"{p.parent.name}/{p.name}:{i}: {m.group(1)} tagged {m.group(2)}, registry has {reg_tags[m.group(1)]}")

# ---------- check 11 (R3 F-10): vocabulary scan of convergence/ and the group change-request files ----------
ALLOWED = re.compile(r"complete relative to M\b")
for p in sorted((ROOT / "convergence").glob("*.md")) + MOVED + sorted(GROUPS.glob("*/change-requests.md")):
    for i, line in enumerate(read(p).splitlines(), 1):
        probe = ALLOWED.sub("", line)
        for m in FORBIDDEN.finditer(probe):
            hard.append(f"{p.parent.name}/{p.name}:{i}: forbidden word {m.group(0)!r}")
        for m in RATE.finditer(probe):
            hard.append(f"{p.parent.name}/{p.name}:{i}: rate wording {m.group(0)!r}")

# ---------- check 12 (R3 F-02): C1-C4 and obligations #1-#6 cited in section 6, explicit mentions ----------
cmap = {f"C{i}": [] for i in range(1, 5)}
omap = {f"#{i}": [] for i in range(1, 7)}
range_form = []
for rid, r in routes.items():
    s6 = str(r["s6"])
    for c in cmap:
        if re.search(r"\b" + c + r"\b", s6):
            cmap[c].append(rid)
    if re.search(r"#1\s?[–-]\s?#?6", s6):
        range_form.append(rid)
    for o in omap:
        if re.search(r"(?<![\d–-])" + re.escape(o) + r"(?!\d)", s6):
            omap[o].append(rid)
print("section-6 citations (explicit): " + " · ".join(f"{k} {len(v)}" for k, v in cmap.items()) + " · " + " · ".join(f"{k} {len(v)}" for k, v in omap.items()) + f" · '#1–#6' range form in {len(range_form)} ({', '.join(range_form)})")
if "--mapping" in sys.argv:
    for k, v in list(cmap.items()) + list(omap.items()):
        print(f"  {k}: {', '.join(v)}")

# ---------- counts and output ----------
counts = {dname: 0 for dname in DISPOSITIONS}
for r in routes.values():
    if r["disposition"] in counts:
        counts[str(r["disposition"])] += 1
print(f"ledger routes {len(ledger)} · route files {len(routes)} · matrix cells {matrix_cells} · registry rows {len(registry_ids)}")
print(f"headers on the freeze3 ids: {header_counts.get('freeze3', 0)} · on the freeze2 ids: {header_counts.get('freeze2', 0)} · on the current-v5 ids: {header_counts.get('current-v5', 0)} · on the current ids: {header_counts.get('current', 0)} · on the gate ids: {header_counts.get('gate', 0)}")
print("dispositions: " + " · ".join(f"{k} {v}" for k, v in counts.items()))
for g in GROUP_ORDER:
    if g in pres:
        print(f"{g}: {len(pres[g]['rows'])} rows; does not preserve: {sorted(pres[g]['does_not_preserve']) or 'none'}")  # type: ignore[index]
proposed_all = [(rid, s) for rid, r in routes.items() for s in r["proposed"]]  # type: ignore[union-attr]
print(f"proposed-evidence rows: {len(proposed_all)}; obligation bullets: {sum(len(r['obligations']) for r in routes.values())}")  # type: ignore[arg-type]

if "--proposed" in sys.argv:
    for rid, s in proposed_all:
        print(f"{rid}: {s}")
if "--obligations" in sys.argv:
    for rid, r in routes.items():
        for o in r["obligations"]:  # type: ignore[union-attr]
            print(f"{rid}: {o}")
if "--table-out" in sys.argv:
    out = Path(sys.argv[sys.argv.index("--table-out") + 1])
    lines = ["| route | adversary action (route file §1) | condition violated | what stops it | disposition |", "|---|---|---|---|---|"]
    for g in GROUP_ORDER:
        for rid in sorted(r for r in routes if routes[r]["group"] == g):
            r = routes[rid]
            lines.append(f"| {rid} | {r['s1']} | {r['violates']} | {r['stops']} | {r['disposition']} |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"table written: {out} ({len(lines) - 2} rows)")

if soft:
    print("\nSOFT:")
    for s in soft:
        print("  " + s)
if hard:
    print("\nHARD:")
    for h in hard:
        print("  " + h)
    sys.exit(1)
print("\nno hard findings")
