---
role: step 4 evidence map — which engine-build evidence (04 v11, EV-163–EV-288) realizes each `[S]` row cited by a route file, and the closing properties of the three remainder slots; read by the route re-run agents of step 4
date: 2026-10-19
based_on:
  registry_blob: "bae8d231316b294f"       # 04 v11
  validation_blob: "0ec579941699c576"     # ExperimentLab/engine/validation.md at commit c834ebbd (HEAD; engine code as at 3ec67985)
  validation_blob_v7: "3d35d8704cd79b5e"  # the blob 04 v7 copied
  requirements_blob: "20acd533e99dd35c"   # engine-requirements.md
---

# Step 4 evidence map

What this file is: a lookup table for the route re-runs of [step4-brief.md](step4-brief.md) §4. It states, for
each `[S]` row of [04-evidence-registry.md](../spine/04-evidence-registry.md) that a route file cites, which
engine-requirements lines the validation record (validation.md,
"val") maps it to, val's result in val's own words, the version 7 rows that now back it, and whether a part of
it is still only stated. It states no disposition; routes appear only in the "cited by" column.

Reading the columns:

- **engine-requirements line(s)** — val's "行号"; "—" where engine-requirements has no entry.
- **val result** — copied from the result column of each named row (满足（测试）, 满足（代码阅读）, 超出范围,
  部署前提, …) at the HEAD blob `0ec579941699c576`; at that blob rows 145, 146, 151, 170, 191, 193 and 209 read
  满足（测试加代码阅读） (04 §2, version 8 paragraph).
- **new EV IDs** — rows EV-163–EV-288 of 04 v11 that record the realization: run observations (tag M) and
  readings of the project's own code (tag R), each row naming its val row in the note.
- **still `[S]`?** — "no": every clause of the `[S]` row is realized and checked by a test, a fuzz run or a code
  reading; a deployment precondition that the engine does not check is named as a premise and does not count
  as `[S]` (step4-brief §1). "partly": a clause has no realization or no check. "yes": the item is outside the
  build (val 超出范围). All evidence is from the prototype at commit 3ec67985 (EV-252: the test added at c834ebbd) on the WSL2 development host
  (kernel 6.6.87.2-microsoft-standard-WSL2), under the diagnostic seccomp policy, with the model chain and the
  resources as stub connectors.

Counts: 69 cited `[S]` rows — 66 no, 2 partly (EV-72, EV-125), 1 yes (EV-129). Version 11: EV-128 moves from partly to no (engine commit 9981dd7b). Version 10: EV-81 and EV-139
move from yes to no, their supervisor clause now a stated deployment premise (fifth design revision as amended, cgroup form only; EV-273–EV-282). Version 8
adds the fifteen `[S]` rows that the step 4 route files cite for the first time (EV-111, EV-112, EV-114, EV-126,
EV-127, EV-151, EV-152, EV-153, EV-155, EV-157, EV-158, EV-159, EV-160, EV-243, EV-244).

## 1 Cited `[S]` rows

| `[S]` EV | engine-requirements line(s) | val result | new EV IDs | still `[S]`? | cited by |
|---|---|---|---|---|---|
| EV-02 | 128, 129 | 128 满足（测试加代码阅读）; 129 满足（测试加代码阅读） | EV-199, EV-200 | no — one uid per execution, taken only from the workspace record, and refusal while it is held are realized (code reading, EV-200; test, EV-199); the refusal on uid-pool exhaustion rests on code reading only (no path picks another uid), see the final section | R-G1-05, R-G4-01, R-G5-06, R-GX-04 |
| EV-03 | 139, 140, 169 | 139 满足（测试加代码阅读）; 140 满足（代码阅读）; 169 满足（测试加代码阅读） | EV-186, EV-187, EV-174 | no | R-G1-02, R-G2-08, R-G3-04, R-G5-05 |
| EV-04 | 254, 255, 191 | 254 实现部分满足（测试）; 255 实现部分满足（代码阅读加回归）, 部署部分为部署前提; 191 满足（测试加代码阅读） | EV-212, EV-213, EV-211, EV-148, EV-149 | no — the order is realized and read (EV-212) and the resulting posture observed (EV-213); the filter installed last is the diagnostic policy, the production allow-set staying with EV-129 | R-G1-06, R-G2-05, R-G5-03, R-G5-07 |
| EV-16 | 130, 205, 206, 210 | 130 满足（代码阅读）; 205 满足（测试）; 206 满足（测试）; 210 满足（代码阅读加回归） | EV-200, EV-203, EV-204, EV-205, EV-206 | no — the absence of a /proc scan is by code reading (EV-205 note) | R-G1-05, R-G4-01, R-G5-06, R-GX-01, R-GX-02, R-GX-03, R-GX-04, R-GX-05 |
| EV-19 | — (engine-requirements has no entry for it) | — (no val row) | EV-235 | no — realized as an absence, established by a text search of the code only; no validation row and no test | R-G4-01, R-G5-06, R-GX-04 |
| EV-30 | 254 | 实现部分满足（测试）; C1 本身随构建进入部署 | EV-212, EV-213, EV-211, EV-246, EV-148, EV-149 | no — three equal values set and re-read before the filter; the uid applied is the record's own (EV-246); equal real, effective and saved uid observed in the agent reports | R-G1-06, R-G5-03, R-G5-07 |
| EV-31 | 255, 191 | 255 实现部分满足（代码阅读加回归）, 部署部分为部署前提; 191 满足（测试加代码阅读） | EV-212, EV-213, EV-214, EV-215, EV-179, EV-262 | no — the first half observed (empty capability sets, no_new_privs) and read; the second half by the policy compiler's clauses for any allow list (EV-215), the clone without CLONE_NEWUSER (EV-179) and the agent probes under the diagnostic policy (EV-214); the nosuid mounts of the deployment are a premise (row 255) | R-G2-05, R-G5-04, R-G5-07 |
| EV-33 | 219, 256 | 219 满足（测试）; 256 部署前提（开发机读数：映射成立） | EV-163, EV-164, EV-165 | no — the self-check is realized and passes in the product on the development host; the initial-namespace half (S13) is a deployment premise, not an `[S]` item | R-G1-02, R-G2-06, R-G2-12, R-G5-05, R-G5-06 |
| EV-34 | 144, 145, 146, 157, 166, 178 | 144 满足（测试）, 以更严格方式; 145 满足（测试加代码阅读）, 回归运行器对次序有专门断言; 146 满足（测试加代码阅读）; 157 满足（代码阅读加 fuzz）; 166 满足（测试）; 178 满足（测试加 fuzz） | EV-177, EV-178, EV-179, EV-180, EV-252, EV-237, EV-171, EV-176, EV-167 | no — the PASSCRED-before-clone order is observed on one diagnostic-fixture case only (EV-178) and read in the spawner (EV-179) | R-G1-01, R-G2-01, R-G2-03, R-G2-05, R-G5-05, R-GX-01 |
| EV-40 | 166, 239 | 166 满足（测试）; 239 满足（测试） | EV-171, EV-175, EV-176, EV-224, EV-225 | no | R-G2-01, R-G2-03, R-G2-06, R-G3-01, R-G3-03, R-G3-04, R-G5-05 |
| EV-41 | 139, 140, 169, 173 | 139 满足（测试加代码阅读）; 140 满足（代码阅读）; 169 满足（测试加代码阅读）; 173 满足（测试加代码阅读） | EV-186, EV-169, EV-174, EV-188 | no | R-G1-02, R-G1-03, R-G1-05, R-G2-08, R-G2-09, R-G2-10, R-G2-13 |
| EV-72 | — (no entry; row 257 gives the spawner CAP_KILL as a premise) | — (no val row) | EV-234 | partly — the engine's unprivileged posture is observed in every case and the spawner runs as a separate process; the spawner's own capability set and the "holds nothing" property of a pre-forked spawner are neither recorded nor checked | R-GX-04 |
| EV-78 | 157–178, with 171 and 172 (val §3) | val §3: every row 满足 in one of its forms except 177 超出范围 | EV-169–EV-175, EV-181–EV-183, EV-197, EV-230, EV-238, EV-247–EV-251, EV-253 | no — the product receive path, the VerifiedContext and dispatch exist and are checked, dispatch up to the stub handlers; received_at is taken when the C reader hands over the whole frame (receive.py:289), the first-version choice that conn's receive-side supplement states, and the cross-fragment pid summary is not recorded (row 168, stricter; EV-249, EV-250) | R-G1-01, R-G2-01, R-G2-02, R-G2-03, R-G2-04, R-G2-06, R-G2-07, R-G2-08, R-G2-09, R-G2-10, R-G2-11, R-G2-13, R-G3-01, R-G3-02, R-G3-03, R-G3-04, R-G3-05, R-G5-03, R-G5-05, R-GX-01, R-GX-02, R-GX-03, R-GX-05, R-GX-06 |
| EV-81 | 252, 218 | 252 部署前提（开发机读数：成立）; 218 部署前提：方法 2026-10-19 写入设计（以内核持有的事实为据：cell 独占 cgroup 的 populated 0）；首版不做重启恢复，engine 侧无可测部分；开发机读数：cgroup 域清空探针的四项内核行为成立 | EV-273–EV-277, EV-278–EV-281, EV-282 | no — all three clauses are deployment preconditions, which count as premises, not `[S]` items: the exclusive uids (row 252, development-host reading holds); the supervisor's tracking of the process domain, whose method the fifth design revision, as amended, now states as a kernel-held fact, the cell's cgroup reporting populated 0, with the pid-namespace reap excluded because a restarted releaser cannot re-read it (EV-273–EV-277), and whose kernel behaviour was probed on the development host (EV-278–EV-280: one run, sleep processes, no privileged-agent case; EV-281 measured the excluded form); frozen sources have no val row | R-G1-02, R-G1-05, R-G4-01, R-G5-06, R-G5-08, R-GX-02, R-GX-04 |
| EV-96 | 139, 149 | 139 满足（测试加代码阅读）; 149 满足（测试加代码阅读） | EV-186, EV-194, EV-196 | no | R-G1-02, R-G1-03, R-G2-04, R-G2-08, R-G2-10, R-G3-01, R-G3-02, R-G3-03, R-G3-05, R-GX-01, R-GX-02, R-GX-03, R-GX-05, R-GX-06 |
| EV-99 | 144 | 满足（测试）; 以更严格方式 | EV-177, EV-180 | no | R-G1-01, R-G2-09 |
| EV-100 | 145, 146 | 145 满足（测试加代码阅读）, 回归运行器对次序有专门断言; 146 满足（测试加代码阅读） | EV-178, EV-179, EV-180, EV-252 | no — the option is set by the spawner on the engine's end before clone, as the design places it | R-G1-01 |
| EV-101 | 143, 176 | 143 满足（测试）; 176 满足（测试） | EV-185, EV-184 | no | R-G1-02 |
| EV-102 | 141 | 满足（测试加代码阅读） | EV-240, EV-190, EV-189 | no | R-G1-03, R-GX-02, R-GX-06 |
| EV-103 | 184, 185 | 184 满足（测试加代码阅读）; 185 满足（测试） | EV-218, EV-219, EV-220, EV-168, EV-196 | no | R-G1-03, R-GX-02, R-GX-06 |
| EV-104 | 188 | 满足（测试加代码阅读） | EV-207, EV-209 | no | R-G1-05 |
| EV-105 | 190 | 满足（测试） | EV-208, EV-209 | no — the uid/gid-mismatch negative is now exercised (bad-uid, bad-gid) | R-G1-05, R-G1-06 |
| EV-106 | 129, 131, 253 | 129 满足（测试加代码阅读）; 131 满足（测试）; 253 部署前提（开发机读数：成立） | EV-199, EV-200, EV-202 | no — one workspace per uid is enforced at start-up (EV-202); the directory itself is a deployment premise (row 253) | R-G1-05 |
| EV-107 | 187 | 满足（测试） | EV-221 | no | R-G1-05, R-GX-02 |
| EV-108 | 192 | 满足（代码阅读加回归） | EV-210 | no — the SEALED uid-mismatch branch is read, not exercised (EV-210 note) | R-G1-06 |
| EV-109 | 193 | 满足（测试加代码阅读） | EV-210, EV-211 | no | R-G1-06 |
| EV-110 | 172, 173 | 172 满足（测试）; 173 满足（测试加代码阅读） | EV-172, EV-183, EV-169, EV-253 | no | R-G3-01, R-G3-05, R-GX-06 |
| EV-111 | 232, 244 | 232 满足（测试加代码阅读）; 244 满足（测试） | EV-254, EV-228, EV-223 | no — no retry and a terminal on a failed start by code reading (EV-254); a repeated request id closes the session (EV-228); late results reach only their own entry (EV-223) | R-G3-01 |
| EV-112 | 244 | 满足（测试） | EV-228 | no | R-G3-01 |
| EV-113 | 237, 238, 231 | 237 满足（测试）; 238 满足（测试）; 231 满足（测试加代码阅读） | EV-224, EV-225, EV-183, EV-230 | no | R-G3-01, R-G3-03, R-G3-04, R-G3-05 |
| EV-114 | — (val row 172 remarks on the hook) | row 172 满足（测试）; its remark that the E-09 hook does not exist in the first version does not match the code (final section) | EV-255 | no — the hook point exists, holds no observer in the product, and its return value is discarded | R-G3-01 |
| EV-115 | 236, 240 | 236 满足（测试加代码阅读）; 240 满足（代码阅读） | EV-229, EV-228 | no | R-G3-02, R-GX-05 |
| EV-116 | 227, 229 | 227 满足（测试）; 229 满足（测试） | EV-226, EV-227 | no | R-G3-02, R-G3-05 |
| EV-117 | 233, 234, 208 | 233 满足（测试）; 234 满足（测试）; 208 满足（测试加代码阅读） | EV-197, EV-198, EV-223 | no | R-G3-02, R-GX-05 |
| EV-118 | 236 | 满足（测试加代码阅读） | EV-228, EV-229 | no — the case of two sessions ACTIVE at once is by code reading only (val row 236) | R-G3-02, R-G3-05 |
| EV-119 | 229, 230, 245 | 229 满足（测试）; 230 满足（测试加代码阅读）, 不提供改绑, 比条款更严; 245 满足（测试） | EV-226, EV-227 | no — the build has no rebind entry, which is stricter than the statement | R-G3-02, R-G3-05 |
| EV-120 | 229 | 满足（测试） | EV-226, EV-227 | no | R-G3-02 |
| EV-121 | 176, 229, 231 | 176 满足（测试）; 229 满足（测试）; 231 满足（测试加代码阅读） | EV-184, EV-227 | no — the agent sends no grant field (grant_ref is rejected as an identity-like field) and the grant comes from the entry's binding; the schema revision itself is a design matter | R-G3-02, R-G3-05 |
| EV-122 | 240, 241, 246 | 240 满足（代码阅读）; 241 满足（测试加代码阅读）; 246 满足（代码阅读） | EV-229, EV-230, EV-231, EV-261 | no | R-G3-02, R-G3-03, R-G3-04, R-G3-05, R-GX-05 |
| EV-123 | 226, 231 | 226 满足（测试加代码阅读）; 231 满足（测试加代码阅读） | EV-241, EV-197, EV-198 | no — realized and read (EV-241); the one-use passage of the operation is by code reading only | R-G3-01, R-G3-03, R-G3-05 |
| EV-124 | 233, 234, 161 | 233 满足（测试）; 234 满足（测试）; 161 满足（测试加代码阅读） | EV-197, EV-198, EV-190, EV-192 | no | R-G3-03, R-G3-05, R-GX-03, R-GX-05 |
| EV-125 | 233, 246 | 233 满足（测试）; 246 满足（代码阅读） | EV-242, EV-257, EV-231, EV-197 | partly — the per-Channel writer, its FIFO, its one sendmsg, the entries' closures over their own RequestEntry (EV-257) and the workers' posting through the executor are realized; a queued entry holds its owner and a build function, so its bytes are fixed when it is taken for sending, not when it is queued (EV-242); no val row checks the FIFO's frame discipline | R-G3-03 |
| EV-126 | 237, 238 | 237 满足（测试）; 238 满足（测试） | EV-224, EV-225 | no | R-G3-01, R-G3-04 |
| EV-127 | 164, 166, 178 | 164 满足（测试加 fuzz）; 166 满足（测试）; 178 满足（测试加 fuzz） | EV-171, EV-172, EV-174, EV-175, EV-176, EV-181, EV-258 | no | R-G3-04 |
| EV-128 | 220, 259 | 220 满足（测试）：设置后检查 FORCE 位；真实内核上再请求 PR_SPEC_ENABLE 得 EPERM (val blob `402334622e082e5e`); 259 部署前提（开发机读数已记录） | EV-283, EV-284, EV-232 | no — since commit 9981dd7b the engine sets PR_SPEC_FORCE_DISABLE, as scope S14 names, and checks the FORCE bit (EV-283), tested on the development kernel (EV-284; EV-233 records the earlier PR_SPEC_DISABLE); the host half is a deployment premise | R-G5-02 |
| EV-129 | 177 | 超出范围（P2b；BUILD-PLAN §1"不做"，rr E-08 第 889–890 行列为部署输入） | — | yes — the production allow-set is outside the build; only the diagnostic policy ran | R-G1-01, R-G1-02, R-G1-03, R-G1-05, R-G1-06, R-G2-01, R-G2-02, R-G2-05, R-G2-09, R-G3-01, R-G3-02, R-G3-03, R-G3-04, R-G3-05, R-G4-01, R-G5-03, R-G5-04, R-G5-05, R-G5-07, R-G5-08, R-GX-01, R-GX-02, R-GX-03, R-GX-04, R-GX-05, R-GX-06 |
| EV-130 | 131 | 满足（测试）。主机身份只按 uid 经 NSS 查（pwd.getpwuid） | EV-201, EV-202 | no — host identities are checked through NSS only | R-G1-02, R-G5-05 |
| EV-131 | 174, 157 | 174 满足（测试加代码阅读）; 157 满足（代码阅读加 fuzz） | EV-236, EV-238, EV-171 | no | R-GX-01 |
| EV-132 | 157 | 满足（代码阅读加 fuzz） | EV-237, EV-166 | no | R-GX-01 |
| EV-133 | 147, 202 | 147 满足（测试）; 202 满足（测试） | EV-192, EV-193, EV-191 | no | R-GX-01, R-GX-03, R-GX-06 |
| EV-134 | 185 | 满足（测试） | EV-219 | no | R-GX-02 |
| EV-135 | 143, 201 | 143 满足（测试）; 201 满足（测试） | EV-222, EV-185 | no | R-GX-02 |
| EV-136 | 201 | 满足（测试） | EV-222, EV-239 | no | R-GX-02, R-GX-06 |
| EV-137 | 207, 208 | 207 满足（测试）; 208 满足（测试加代码阅读） | EV-223, EV-196 | no | R-GX-05 |
| EV-138 | 141, 147, 148, 161 | 141 满足（测试加代码阅读）; 147 满足（测试）; 148 满足（测试加代码阅读）; 161 满足（测试加代码阅读） | EV-189, EV-190, EV-191 | no — fd-number reuse through the real spawner happens in sequence (EV-189); reuse inside one round is made by the tests (EV-190, EV-191) | R-GX-03 |
| EV-139 | 218, 217 | 218 部署前提：方法 2026-10-19 写入设计（以内核持有的事实为据：cell 独占 cgroup 的 populated 0）；首版不做重启恢复，engine 侧无可测部分；开发机读数：cgroup 域清空探针的四项内核行为成立; 217 满足（测试）, 后半句由构造满足 | EV-216, EV-217, EV-273–EV-277, EV-278–EV-281, EV-282 | no — the engine side is realized (the engine exits on control loss and recovers no old epoch, EV-217); the supervisor's confirmation is now a stated deployment precondition, a premise, resting on a kernel-held fact, the cell's cgroup reporting populated 0, the pid-namespace reap excluded (EV-273–EV-277), whose behaviour was probed on the development host only (EV-278–EV-280; one run, sleep processes, no privileged-agent case); the agent cannot leave the cell's cgroup by the sandbox mounts (EV-282) | R-GX-04 |
| EV-140 | 216, 217 | 216 满足（测试加代码阅读）; 217 满足（测试） | EV-216, EV-217 | no | R-GX-04 |
| EV-141 | 133, 142 | 133 满足（测试加代码阅读）; 142 满足（测试加代码阅读） | EV-195, EV-196, EV-190 | no | R-GX-05 |
| EV-151 | 147, 148, 149 | 147 满足（测试）; 148 满足（测试加代码阅读）; 149 满足（测试加代码阅读） | EV-194, EV-193, EV-187, EV-190 | no | R-GX-06 |
| EV-152 | 139 | 满足（测试加代码阅读） | EV-186, EV-187 | no | R-G3-05, R-GX-06 |
| EV-153 | 142 | 满足（测试加代码阅读） | EV-195 | no | R-GX-06 |
| EV-155 | 163 | 满足（测试加代码阅读） | EV-191, EV-192 | no — checked for the epoll backend only; the fd-number reuse in the run is made by os.dup2 | R-GX-06 |
| EV-156 | 226 | 满足（测试加代码阅读） | EV-197, EV-198, EV-196 | no — checked up to the stub handlers; the decoy replaces the execution_id key only | R-G3-01, R-G3-02, R-G3-03, R-G3-05 |
| EV-157 | 246 | 满足（代码阅读） | EV-231, EV-261 | no — by code reading only | R-G3-05, R-GX-06 |
| EV-158 | 203, 204 | 203 设计已写明（严格读法），实现一致; 204 设计已写明（严格读法），实现一致 | EV-264, EV-205, EV-192 | no — by code reading only | R-GX-06 |
| EV-159 | 226 | 满足（测试加代码阅读） | EV-259, EV-197 | no | R-G3-05 |
| EV-160 | 243 | 由构造满足（不存在按 execution 的选择） | EV-259 | no — there is no per-execution provider choice in the build | R-G3-05 |
| EV-243 | 176, 229 | 176 满足（测试）; 229 满足（测试） | EV-184, EV-227 | no | R-G3-01, R-G3-02, R-G3-05 |
| EV-244 | 176, 164 | 176 满足（测试）; 164 满足（测试加 fuzz） | EV-184, EV-172, EV-258 | no | R-G3-02 |

## 2 Remainder slots

Closing properties as PLAN §Follow-up plan after U states them (the seven-slot table).

| slot | closing property | new EV IDs | established? |
|---|---|---|---|
| R-G2-11 | bytes reach the comparison only through the one FrameReader path; the parser has no memory error | EV-169, EV-170, EV-171 (the path); EV-265, EV-266 (since commit 7b4ab727 no JSON call lies between the comparison and the copy-out; the body is parsed only by Python's json); EV-267, EV-268, EV-269 (ASan/UBSan fuzz rerun of the C reader, the ancillary check and the control parser at 7b4ab727; EV-166–EV-168 are the earlier run, on the reader that still parsed the body with jansson); EV-270, EV-271, EV-272 (the regression and integration reruns; a malformed body is now rejected by the Python parse); EV-236; EV-260, EV-261 | yes, within the limits of the named check — the path half by code reading and static tests (EV-169, EV-170, EV-265, EV-266); the memory-safety half as the fuzz rerun can give it: one run of one hour per entry, no sanitizer report, crash or oracle failure, no repetition, every line of w2_frame_receive executed. On jansson: since 7b4ab727 no third-party parser runs on agent bytes in C; jansson remains only in the control-record parser, whose input comes from the trusted spawner and which runs uninstrumented in the control entry. The Python json parse of the copied frame is not fuzzed and rests on the CPython runtime (val row 175 at blob `46470dfcda0acae1`) |
| R-G2-12 | the engine runs under the identity map; the start-up self-check passes in the product | EV-163, EV-164, EV-165, EV-262 (no engine path moves the engine into another user namespace) | yes — the product entry recorded the identity map in all 31 cases with a startup field and refused service under a one-line non-identity map; on the development host only; that the engine's namespace is the initial one stays a deployment premise (val row 256, S13) |
| R-G2-13 | one comparison point on the only path from recvmsg to the buffer, every phase through it | EV-171, EV-172, EV-173, EV-174, EV-251, EV-253, EV-239 | yes — by code reading of the C reader and of receive_step, with the root unit test across STARTING, ACTIVE and DRAINING and the pre-read check for a CLOSED session; limits as val states them: in the negative cases the frames share one code path and differ only in the failure position, the phase rule ran on a stand-in row, and a wrong-uid case through the full lifecycle exists only in STARTING |

AA-13 (the event library delivers no readiness for a deregistered fd number; val §AA-13, run
20261018T152246Z-aa13-deregistration): EV-191 (the run, with its negative control) and EV-192 (the code);
the design statement EV-155 is in table 1. Limits: the epoll
backend only, and the fd-number reuse made by os.dup2, not by the spawner's handoff.

## Validation rows not confirmed

- **Row 129 (one holder per lease; refusal on pool exhaustion), confirmed in part — resolved by 9981dd7b:** val at blob `402334622e082e5e` now states that test_pool_exhaustion_refuses tests the execution-slot limit and that the uid clause rests on code reading. Original finding: val cites
  test_pool_exhaustion_refuses for the exhaustion clause. That test launches 16 executions on 16 of the 21
  workspaces in the test catalog and is refused at the execution-slot limit (lifecycle.py:135–136,
  EXECUTIONS_MAX = 16), not by a shortage of uids; and test_refusals_create_no_row is refused at the workspace
  check (L137–138) before the held-uid check (L140) is reached. The clause "refuses to start rather than reuse
  a uid" is therefore supported by code reading only (EV-200: the uid comes only from the workspace record and
  no path picks another), not by a test; 04 v7 registers no test row for it (note of EV-199).
- **Row 220 (indirect-branch opt-in), confirmed for its own sentence; a gap against EV-128 — resolved by 9981dd7b:** the engine now sets PR_SPEC_FORCE_DISABLE and checks the FORCE bit (EV-283, EV-284), and val row 220 says so. Original finding: The test and the
  code support "opts in per task (prctl) before holding secrets". scope S14, which EV-128 registers, names
  PR_SPEC_FORCE_DISABLE; the engine uses PR_SPEC_DISABLE (startup.py:85, EV-233), which the task itself could
  later re-enable. This bears on the hardware-side residual, not on uid attribution.
- **Row 172 (one VerifiedContext constructor), confirmed for its result; its remark not — resolved by 9981dd7b:** val row 172 now says the pre_egress hook point exists, observe-only, with no observer in the product. Original finding: The result holds
  (EV-183, EV-253). The remark that the E-09 hook named by the clause does not exist in the first version does
  not match the code: requests.py:114 and :222–232 hold an observe-only pre_egress hook point, empty in the
  product, whose return value is discarded (EV-255; G3 change request 5, for the engine side).

## Proposals not registered (version 8)

Proposed-evidence items of the step 4 route files that 04 v8 and v9 do not register, because nothing could be
checked against a source in this session: a run not yet made, or a reading at the pinned kernel tag
linux-msft-wsl-6.6.87.2, whose tree is not in this workspace. Each stays in its route file with that note.

| proposed in | proposal | reason |
|---|---|---|
| R-G2-01 | an integration case with the bootstrap FAIL record sent in the hello phase | run not yet made |
| R-G2-03 | a kernel-generated MSG_CTRUNC on the data channel, or a pinned-tag reading that no sender can produce one against this buffer | run not yet made; kernel tree not in this workspace |
| R-G2-04 | an integration case with two channels whose partial frames interleave with executor turns | run not yet made |
| R-G2-06 | a root unit case with pool uids above 2^31 | run not yet made — made 2026-10-20 (engine b262e80e), registered in 04 v12 as EV-289, EV-290 |
| R-G2-07 | a root unit case with the change of sender at the frame's last byte | run not yet made — made 2026-10-20 (engine b262e80e), registered in 04 v12 as EV-291 |
| R-G2-08 | a root unit case with two rows whose expected uids are swapped relative to the sending channels | run not yet made — made 2026-10-20 (engine b262e80e), registered in 04 v12 as EV-292 |
| R-G2-09 | a root unit case in which a different-uid task holds a duplicate of the agent end and sends with a pid equal to a task of X | run not yet made — made 2026-10-20 (engine b262e80e), registered in 04 v12 as EV-293, EV-294 |
| R-G2-10 | an integration case with two live executions under one recurring local_agent_id | run not yet made |
| R-G2-11 | a fuzz entry linking an ASan-instrumented jansson and driving the body parse | run not yet made; since commit 7b4ab727 the C reader no longer calls jansson (EV-265), so the proposal no longer bears on the data path |
| R-G2-13 | a wrong-uid case through the full lifecycle in ACTIVE and in DRAINING | run not yet made |
| R-G4-01 | SOCK_STREAM skb survival at the pinned tag (P-32) | kernel tree not in this workspace; stays P-32 in 04 §5 |
| R-G4-01 | an integration case with a forked descendant of PID 1 alive at the stop | run not yet made |
| R-G5-05 | map_write admits a child extent only inside one parent extent, so a full single extent is a bijection | kernel tree not in this workspace |
| R-G5-05 | user:[4026531837] is PROC_USER_INIT_INO, the initial user namespace | kernel tree not in this workspace |
| R-G5-05 | the engine's own user-namespace link recorded in its startup posture | run not yet made |
