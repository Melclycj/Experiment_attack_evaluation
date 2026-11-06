# Design-revision recheck brief — third revision of 2026-10-18

Written 2026-10-18 by the executor; one brief for both reviewers (Claude Opus and Codex, cold context, user
approval 2026-10-18). Repository root `<repository root>`, branch main. The revision under check is commit `820d4529`
(its record is corrected for a count in `7f49fee7`). You have no access to the executor's conversation, you
edit nothing in the repository, and you write exactly one file.

## What you write

- Claude Opus: `Thesis/Work/Submission/prove/uid-binding/work/reviews/DR-recheck-2026-10-18.md`
- Codex: `Thesis/Work/Submission/prove/uid-binding/work/reviews/DR-recheck-addendum-2026-10-18-crossfamily.md`

Three parts. (1) A table with one row per finding listed below: finding, where the revision addresses it
(current file and line), verdict **resolved / partly / not resolved**, and one line of reason. (2) New
findings the revision itself introduced, numbered `N-01`, `N-02`, … each with file and line, severity (P1 = a
requirement lost, weakened or contradicted, or a workload that cannot complete; P2 = an ambiguity an
implementer could read two ways, or a cross-file inconsistency; P3 = wording), the defect in two sentences,
and one line "what would resolve it". (3) A gate line: "may pass" / "may not pass" for starting engine build
step 1 on this design, with the reason. Keep any stdout summary to counts and the file name.

## Scope

Read `git show 820d4529` and `git show 7f49fee7` first, then the changed passages in the current files and
whatever surrounding text you need to judge them. The earlier review records are
`DR-2026-10-18.md` (Opus findings O-F01…O-F21) and `DR-addendum-2026-10-18-crossfamily.md` (Codex findings
C-F01…C-F05) in this folder; the revision record is
`Thesis/Work/Submission/prove/uid-binding/design-revision-2026-10-18.md` § Third revision.

Out of scope: whether the uid binding suffices as an identity argument (R1–R3); the uid-binding line's route,
preservation and spine files; the C code under `ExperimentLab/engine/native/` (the one planned C change is
not yet made). `ExperimentLab/lab/experiments/w2/implementation/engine-design.md` carries another session's
uncommitted edits and is not part of the revision.

## Findings to check (24 distinct)

Two pairs coincide and are checked once: C-F03 = O-F05 (tool calls in completion evidence and post_read);
C-F04 = O-F02 (where the tool definitions live). Three user rulings changed the resolution from what a
finding proposed — judge them as rulings, not as defects:

- O-F01 is resolved by the looser reading: a terminal record awaiting storage release no longer holds its uid
  and lease at spawner admission (conn E-01 identity supplements), so the W2-LW-finish successor is not
  refused; no engine-side wait was added.
- O-F12: the stop for an unknown record stays a control fault; the revision states the blast radius and the
  user's reason.
- O-F15: local-instance cache isolation is two requirements met as deployment preconditions; the engine does
  not check them.

All others: O-F02…O-F11, O-F13, O-F14, O-F16…O-F21, C-F01, C-F02, C-F05.

## Questions besides the table

- Under the looser reading, does W2-LW-finish now complete on the written path, and does anything else in
  conn, rr or si still assume the strict reading (spawner admission, execution slot, storage budget, the
  16 live spawner records)?
- Do the tool-definition, freeze, release-barrier, evidence and post_read changes form one consistent path
  from the catalog to the model and back to the adapter, without the connector reading tool-call semantics?
- Does BUILD-PLAN §1/§2/§5 now match the design (the one C change, the blobs, the check), and are its two
  notes on reused spawner behaviour (wait error ends the control epoch; kill error after an earlier
  spawn_failed sends nothing and the engine quarantines on the 5,000 ms empty deadline) consistent with conn
  E-01/E-04?
