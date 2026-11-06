---
title: Group-cut inputs — transitions that fall into two groups, and families outside E-01–E-04
date: 2026-10-12
source: the plan-consistency review of 2026-10-12 (cold-context reviewer reading the frozen design)
status: input to Step 2's group cut; a reviewer's reading, to be re-derived from the frozen text at Steps 1–2, never copied
frozen_text: connections.md at blob 74b136585c4064e1 (line numbers below refer to it)
---

# Group-cut inputs (2026-10-12)

The provisional groups are G1 launch-admission · G2 receive-and-check · G3 request-and-dispatch ·
G4 close-and-reclaim · G5 boundary. Step 1 extracts the transitions; Step 2 assigns each to exactly one
group and lists the attribution-irrelevant exclusions. The reviewer's reading below says where that
assignment is not obvious. It is an input, not a decision.

## Transitions the reviewer could place in one group

lease free→held, the RESERVED row and expected_uid (L254, L322) → G1; socketpair and engine-side PASSCRED
(L257, L277) → G1; clone and sandbox steps 1–11 (L258–259, L282–289) → G1; SEALED/COMMIT bootstrap with the
spawner's per-fragment uid/pid check (L289–295) → G1; spawn_prepared fd handoff check (L113, L124–129) → G1;
COMMIT→execve (L297) → G1; per-fragment recvmsg ancillary / CTRUNC / SCM_RIGHTS handling (L413–421) → G2;
per-fragment uid comparison and sentinel rejection (L422–424) → G2; frame decoding into VerifiedContext
(L425–431, L506–518) → G2; the adversary's same-uid fork sending and the four explicit-SCM_CREDENTIALS
sender routes (kernel §5) → G2; admit / prepare / authorize / try_dispatch (L607–618) → G3; handler.start and
sink holding the original objects (L619–620, L641) → G3; the TaskCall state machine and task_call_id match
(L687–695) → G3; close_session six steps (L787–808) → G4; finish / DRAINING / shutdown / bye (L816–821) → G4;
SIGKILL PID 1 then waitpid → execution_empty (L801, L829) → G4; lease quarantined / free and the double gate
(L804–806, L831) → G4; control EOF → quarantine all (L859–868) → G4; N1 / N9 → G5.

## Transitions that fall into two groups (Step 2 must decide)

- the hello frame: travels the E-02 pipeline yet drives the E-01 row STARTING→ACTIVE (L265–266, L325) — G1 / G2
- frame deadline or EOF leading into E-04 (L432–435) — G2 / G4
- execution_empty arriving before prepared / hello (L334–335) — G1 / G4
- control sequence, idempotence, tombstones, duplicate spawn_prepared (L131–142) — G1 / G4
- cleanup_stalled → accepting_new = false (L875–879) — G4 / G1
- a late callback after uid free binding to the old session (L835–837) — G3 / G4
- try_dispatch re-checking Session = ACTIVE (L616) — G3 / G4
- the configuration-failure route (unshare restoring capabilities): its defence sits in G1 (spawn step 11)
  while the plan places the route in G5

## Families with no group (Step 1 must list them as attribution-irrelevant or not, with reasons)

- supervisor hand-over / a new engine epoch in the same cell (L864–867) — identity-relevant but outside
  the E-01–E-04 families
- RuntimeCopy and file-worker storage events (L145–217)
- E-03 capacity rotation (L715–739)
- E-04 effect classification and retry (L887–921)

## Why this matters

The condition × group matrix can be generated from the ledger's (condition, group) columns, but the
transition-partition check needs the explicit transition → group table from Step 2; without it the eight
dual-group transitions surface only at reconcile, when group files may no longer be edited.
