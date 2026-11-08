# Targeted recheck brief — follow-up to the third revision (2026-10-18)

Written 2026-10-18 by the executor; one brief for both reviewers (Claude Opus and Codex, cold context).
Repository root `<repository root>`, branch main. Under check: commit `c0aef66b` only. You edit nothing in the
repository and write exactly one file.

## What you write

- Claude Opus: `Thesis/Work/Submission/prove/uid-binding/work/reviews/DR-recheck2-2026-10-18.md`
- Codex: `Thesis/Work/Submission/prove/uid-binding/work/reviews/DR-recheck2-addendum-2026-10-18-crossfamily.md`

(1) A table, one row per item below: where `c0aef66b` addresses it (file and line), verdict **resolved /
partly / not resolved**, one line of reason. (2) New findings introduced by `c0aef66b` only, numbered
`M-01`, … with file and line, severity (P1 = a requirement lost, weakened or contradicted, or a workload that
cannot complete; P2 = an ambiguity an implementer could read two ways, or a cross-file inconsistency; P3 =
wording), two sentences, one line "what would resolve it". (3) A gate line: "may pass" / "may not pass" for
starting engine build step 1, with the reason. Keep any stdout summary to counts and the file name.

## Items (from the recheck records in this folder, `DR-recheck-2026-10-18.md` and its crossfamily addendum)

Decisions already taken — judge whether the text states them consistently, not whether they are right:

- Opus N-03 = Codex N-02: the reused spawner's two behaviours are written into conn E-01 as they are (kill
  error after an earlier spawn_failed sends nothing, quarantine by the 5,000 ms empty deadline; wait error is
  a control-link fault closing every execution). No C change.
- Opus N-02: the first build's sender_pid is always null and received_at is taken when the C FrameReader
  hands over the whole frame; the 5,000 ms assembly bound stays in C.
- Opus N-09: the uncertain-submission branch is kept unchanged; the stop ruling's reason is qualified by it;
  only send errors known to have sent nothing (EAGAIN, EINTR) are recorded as local.

Text fixes: Opus O-F04 partly = Codex N-01 (budget on the provider-mapped form), Opus N-01, N-04, N-05, N-06,
N-07, N-08, N-10, and the retained-copy clause of N-09.

Read `git show c0aef66b` and whatever surrounding text you need. Out of scope: anything `c0aef66b` did not
touch, the uid binding's sufficiency (R1–R3), the uid-binding line's route/spine files, and the C code.
`ExperimentLab/lab/experiments/w2/implementation/engine-design.md` carries another session's uncommitted
edits and is not part of the revision.
