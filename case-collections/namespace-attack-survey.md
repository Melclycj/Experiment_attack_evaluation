# Research survey — network-namespace attacks and lifetime

> **PERMANENT EVIDENCE FILE**, like `kernel-research-survey.md` *(both
> promoted from staging by user ruling, 2026-08-30)*. Conclusions fold into
> `kernel-namespace-confinement.md` and source rows into
> `source-dependencies.md`; **the file itself is kept**, because writing needs
> the narrative and the citation rather than a claim-table row. **Nothing here is routed** — this is
> evidence, not design text. **Standing requirement (user, 2026-08-30): every claim must name its
> source**; anything that cannot is marked as such rather than left standing.
>
> **Why it exists.** The design rests on *one network namespace per agent*, and that premise had never
> been researched — the five external surveys of 2026-08-28 covered credentials and kernel surface and
> mention network namespaces **zero** times. Commissioned by the user 2026-08-30, run 2026-08-30.
>
> **Six questions in two rounds** (N1–N4 on 2026-08-30, N5–N6 the same day after the first round raised
> lifetime and syscall-route questions it could not answer), each run separately. Each section states the
> question, the answer, the evidence, and what it changes for this design.

---

## N1 · Can one agent enter another agent's network namespace?

**Answer: not without a capability it does not have — and this is now source-backed rather than
inferred.** `setns(2)` is explicit:

> "In order to reassociate itself with a new network, IPC, time, or UTS namespace, the caller must have
> the `CAP_SYS_ADMIN` capability **both in its own user namespace and in the user namespace that owns the
> target namespace**."

That second clause is the one that matters, and it is what closes the user-namespace detour for this half
of the design exactly as the uid map closes it for the identity half. A process that creates its own user
namespace "is granted all capabilities in that namespace" — but a sibling's network namespace is owned by
the **initial** user namespace, which the agent's new namespace does not own. Full capabilities in a
namespace that owns nothing buy nothing.

**What is new: the handle routes are wider than `/proc/[pid]/ns/net`.** `setns` accepts three kinds of
descriptor — the magic links under `/proc/[pid]/ns/`, **bind mounts of those links**, and, since Linux
5.8, a **pidfd** from `pidfd_open(2)` or `clone(2)`. This design passes descriptors over `SCM_RIGHTS` and
has an open question about `SCM_PIDFD` (`kernel-research-survey.md` Q3); a pidfd is therefore not only an
identity handle but a **namespace handle**. It does not break the capability check above, but it widens
what "do not leak a descriptor" has to cover.

**Stated as a loss of depth, which is the accurate form.** Two independent conditions stand between an
agent and a sibling's namespace: *cannot obtain a handle*, and *does not hold the capability*. A pidfd
reaching an agent removes the first and leaves only the second. Nothing is breached — the capability check
is the one that actually refuses — but a two-door construction becomes a one-door construction, and the
design has never counted its doors. The rule that follows is narrow: **descriptor hygiene must name pidfds
explicitly**, because "do not leak the agent's channel fd" reads as complete and is not.

**Null result, logged as such.** No published case was found of an unprivileged process entering another
process's network namespace through `setns` abuse. The well-known descriptor-leak container escapes are a
different object: runc's *Leaky Vessels* (`CVE-2024-21626`) leaks an internal **mount/cwd** descriptor,
letting the container resolve paths into the host's mount namespace. It is a mount-namespace failure with
a filesystem consequence, not a namespace-entry failure.

*Consequence for the derivation:* the three reasons stated in `kernel-namespace-confinement.md` for why an
agent cannot enter a sibling's netns can be upgraded from reasoning to citation for the first one. The
second (cannot obtain the descriptor) must now name pidfds. The third (empty bounding set) was
**exercised the same day** — and the run showed the bounding set is not the thing holding that line: see
the cell below, and `C2` in `kernel-uid-binding.md` §6.

---

## N2 · Can a network namespace outlive the agent, and does that break reclamation?

**Answer: yes, and this is the finding with the sharpest edge for this design.** A network namespace lives
as long as *anything* references it. Three references keep it alive, and only the first is the one the
design watches:

1. a process inside it;
2. an open file descriptor to its `/proc/[pid]/ns/net` link;
3. a **bind mount** of that link.

Route 3 is not hypothetical — it is the documented, standard mechanism: `ip netns` persists namespaces
precisely by bind-mounting the link into `/var/run/netns`, so a namespace with no processes at all stays
alive and re-enterable by name. And it leaks in practice: moby issue **#31414** records network namespaces
plus their interfaces left behind in `/var/run/docker/netns` after every failed prestart hook.

*Consequence for the design, and it is a real one.* The reclamation gate is stated as **one clock** —
namespace, uid and session row live and die together — and the spawner discharges it by reporting
"namespace-empty" from `waitpid`. **Process exit is not namespace death.** A descriptor or mount held
anywhere — by the engine, by a monitoring tool, by a failed spawn path — keeps the namespace alive after
the agent is gone, while the gate reports it empty. Whether the uid may then be recycled while a
re-enterable namespace still carries its name is a question the design has not asked.

**Who can actually create such a reference, and how — because the answer is not who it first appears to
be.** The **engine cannot**: reading `/proc/<agent_pid>/ns/*` needs ptrace-level access over the target,
and the engine is unprivileged and runs under a different uid, so it cannot obtain a handle it might then
leak. The **spawner can**: it is privileged and it is the parent, so those links are open to it, and it
forks by design. Three concrete ways a handle escapes it:

1. sending an fd from `open("/proc/<pid>/ns/net")` across the control socketpair;
2. forking a helper or monitoring process **while such an fd is open** — the child inherits it silently;
3. passing an agent's **pidfd** anywhere (see N1 — a pidfd is a namespace handle).

**The prohibition has two distinct consequences that are easy to collapse into one.** A handle in a third
party's hands (a) **keeps the namespace alive**, which is a reclamation-correctness problem, and (b) **is
the admission ticket for `setns`**, which is a containment problem the moment that third party has the
capability. A rule justified only by (a) will be relaxed the first time (a) stops mattering.

**Inode numbers cannot substitute for this.** Namespace inodes come from nsfs and are **reused** after
destruction, so recording one in a session row and comparing later cannot distinguish two namespaces
across time without a monotonic session counter alongside it.

---

## N3 · What actually happens under a shared network namespace? — the case is published, and severe

**Answer: `CVE-2020-15257`, "ABSTRACT SHIMMER" (NCC Group, December 2020), is precisely the failure this
derivation predicted from the source reading, exploited in production software.**

- `containerd-shim` exposed its API on an **abstract** UNIX socket.
- Any container sharing the network namespace — `docker run --net=host`, or `hostNetwork: true` in
  Kubernetes — could reach it. NCC: *"abstract namespace Unix domain sockets are tied to network
  namespaces"*, whereas *"pathed Unix sockets … cannot generally be accessed from a container with a
  `pivot_root(2)`-ed rootfs."* That is the mount-namespace-versus-network-namespace split of §5 of the
  confinement derivation, stated by an independent party three years before this repo derived it.
- The only access check was identity: *"the only check performed is that the user connecting is the same
  user as the one containerd-shim is running as"* — root, in the standard case, and a host-networked
  container's root **is** the host's root by uid.
- Result: root-equivalent host compromise. The fix was to **abandon abstract sockets for pathed ones**
  under `/run/containerd`.

**Three things this buys, and they are not the same thing.**

1. **It grounds the per-agent network namespace empirically.** The claim "a per-agent mount namespace over
   a shared netns leaves siblings an open, permission-free rendezvous" stops being a source reading and
   becomes a published, exploited case.
2. ~~**It independently confirms the mechanism this thesis uses.**~~ **Corrected 2026-09-07 (independent
   evidence rerun, user-approved).** NCC's *implemented* fix was to move the shim to **pathed** sockets
   (their "The Fix" section). The sentence *"abstract Unix sockets have no built-in access controls, and
   must validate connections dynamically via pulling ancillary data with `recvmsg(2)`"* is NCC's **generic
   advice for anyone who keeps an abstract socket**, not the remedy they adopted — and NCC also warns that
   either peer-credential API carries a PID race. So this case does **not** show NCC choosing this design's
   `SCM_CREDENTIALS` capture; it shows the same *class* of check being recommended and a different remedy
   applied. What survives is item 3, and it is the sharper point: a per-message uid check alone would still
   have accepted equal uid 0.
3. **It is a direct argument for per-agent uids.** The shim *did* check the peer credential; the check was
   useless because the two principals shared a uid. This design's per-agent uid allocation is exactly what
   makes the same check meaningful. The CVE is therefore evidence for two design decisions at once, and
   the honest reading is that credential checking without uid separation is theatre.

**Context worth keeping:** a shared network namespace is not an exotic misconfiguration. It is the
**default** for containers within one Kubernetes pod — sidecars share the netns and reach each other over
`localhost` — and isolating a sidecar from its application container is an open problem rather than a
solved one.

### The mechanism underneath, stated once so the case is not read as an accident

The two ways of addressing a UNIX-domain socket put their **names in different spaces**, and everything
above follows from that:

| | **pathname** | **abstract** |
|---|---|---|
| The name | `/run/x.sock` — a socket-type inode in the filesystem | `\0foo` — a byte string starting with NUL, **not in the filesystem** |
| Where the name lives | the **filesystem** | a hash table **inside `struct net`** |
| Who decides visibility | the **mount** namespace | the **network** namespace |
| Failure when absent | `ENOENT` | `ECONNREFUSED` |
| Permission check | **yes** — the whole of filesystem DAC | **none** — `unix(7)`: *"Socket permissions have no meaning for abstract sockets"* |

A pathname socket inherits the filesystem's access control **and** the mount namespace's isolation for
free. An abstract socket inherits nothing: **its only boundary is the network namespace.** Detail in
`kernel-namespace-primer.md` §4.

**The shim's API was never meant to be reachable by containers.** It served `containerd` itself — the
parent daemon — for lifecycle calls. Abstract addressing was chosen for the daemon's convenience: no mount
point, no path visibility, no cleanup. The failure is therefore not "an API deliberately exposed to
containers" but **an exposure scope wrong by an order of magnitude**: the author wanted *me and my parent*
and the kernel gave *everything in this network namespace*. Host-networked containers sat inside it.

**This design's channel is neither kind, which is one step stronger than containerd's fix.** The agent's
channel is a `socketpair(2)` — two already-connected endpoints, never `bind()`ed, **with no name at all**.
There is nothing to look up, guess, or enumerate, even for a process in the same network *and* mount
namespace. containerd's remedy (move to a pathname socket) restores an object that is *protected*; a
socketpair leaves no object to protect. The cost is that it can only be handed out at creation — nobody
can connect to it later — which is exactly the property the design wants, since the channel is meant to be
a capability rather than an address.

*Consequence:* this attaches to the finding that the network namespace does two jobs, and to the
loopback condition — a raised `lo` under a shared netns is the TCP-shaped version of the same rendezvous.

---

## N4 · How much kernel surface does the network namespace itself open?

**Answer: the surface is real and concentrated, but it is reached through `CAP_NET_ADMIN`, which the agent
never holds.** The exploitation pattern reported across the user-namespace CVE corpus is a fixed chain:
**create a user namespace → map uid 0 → gain `CAP_NET_ADMIN` inside it → open a `NETLINK_NETFILTER`
socket → send crafted `nf_tables` messages.** ~~In the surveyed corpus, **43 % of user-namespace-gated CVEs
sit in `nf_tables` alone**.~~ (Vendor-sourced concentration figure, **retired 2026-09-07 without a
replacement** — the numbers question lives in `kernel-research-survey.md` Q4;
this section carries the chain only.)

*Consequence:* this **names concretely what denying `unshare` buys**, which the repo has so far argued only
in the abstract ("reduces reachable kernel surface"). The chain is cut at its first step. This is the
substance the relocated `CRA-F17` should carry when it moves under the out-of-scope-residual argument.

**Two honest limits.**

- **The quantifications are Q4's question, not this survey's.** `kernel-research-survey.md`
  Q4 records once why every vendor figure ("262 %", "3.4×", the 43 % concentration) is unusable and that no
  peer-reviewed userns-toggle measurement exists; the replacement *method* is
  `boundary-defence-w2-redesign.md`. Use the
  named chain, which is a structural fact — never a number from here.
- **The chain is about the *user* namespace, not the network namespace.** The agent's netns is created by
  a privileged spawner, so the agent never walks the creation path. But the agent still **sits inside** a
  netns, and the realized seccomp profile does not deny `socket` (`CRA-F21`). Whether an agent with no
  capabilities can reach netlink parsing code from inside its own namespace is **not answered here** and
  is a distinct question from the one this section closes.
- ~~**The 43 % figure has the same provenance as the multiplier that was ruled uncitable** … Open.~~
  **Closed 2026-09-07:** retired without a replacement — ACISP 2025's 32/51 is not an equivalent (Q4; the
  rerun report §2.3). The Held `ROUTE-ITEM` at N9 that proposed the swap is superseded by the W2 redesign
  §4 and awaits the user's routing at method-plan §7 step 4; the block itself is left as written.

### Which layer this defence actually belongs to

The deny is easy to file under the wrong argument, and the repo already did that once (`CRA-F17`), so the
layers are separated explicitly:

| What it is asked to protect | Is denying user-namespace creation necessary? |
|---|---|
| **The uid cannot be forged** (identity layer) | **No.** The `uid_map` constraint closes it — an unprivileged writer may map only its own effective uid. This is what overturned `CRA-F17`'s stated role. |
| **The agent cannot re-acquire `CAP_SETUID`** (capability layer) | **Yes, and it is the only line.** Measured 2026-08-30: `unshare(CLONE_NEWUSER)` restores a capability set — bounding set included — that was just emptied. |
| **Reachable kernel surface** (out-of-scope-residual argument) | **Yes, and this is its main justification** — it cuts the `nf_tables` chain at step one. |

So: **denying it is the capability layer's only line, and not a line in the identity layer at all.**
Collapsing the two produces the false statement "`unshare` is denied, therefore the uid is safe" — the
identity layer holds through the map even where the deny is absent.

**One more qualifier the table cannot carry.** The deny is implemented in a seccomp profile, so its
strength is **exactly the strength of that profile being the one actually installed** — and the profile
this design currently points at is `SCMP_ACT_ALLOW` with 18 denials (`CRA-F21`). A default-allow filter is
an enumerate-the-bad construction and cannot be a boundary. That is what makes `S2` (default-deny, with a
written production allow-list) the load-bearing item rather than a tidiness requirement.

---

## What this survey does not settle

**The premise itself was never the weak point — the bookkeeping around it is.** Nothing found here
threatens "one netns per agent" as a *mechanism*. Every real-world failure was one of two shapes: a
namespace deliberately **shared** (N3), or a namespace **outliving** its occupant (N2). Both are
lifecycle-and-configuration failures, which is exactly where this design currently has prose but no
invariant and no check.

**Experiment cell — proposed here and RUN the same day**
(`REPORT-netns-entry.md`, commit
`4bd8928`). It converted the three reasons of N1 from inference to measurement and was also the **first
exercise of the step-11 privilege posture**. Every path returned what the table predicted; the run
additionally measured that `unshare(CLONE_NEWUSER)` **restores the capability bounding set** that step 11
had just emptied, which the design's `C2` condition did not account for. The substrate caveat below was
checked before the run: unprivileged user namespaces are permitted on this image
(`max_user_namespaces` = 63497), so path 3 measured the kernel rule and not an image policy.

| Path | What A attempts | Expected |
|---|---|---|
| 1 | `setns()` into B's netns **with the descriptor handed to it** | `EPERM` — isolates the capability check from the descriptor question |
| 2 | Find B's `/proc/<pid>/ns/net` unaided | not visible — pid namespace + pivot (corroborates d7's `visible_pids: 1`) |
| 3 | `unshare(CLONE_NEWUSER)`, then `setns()` into B's netns | `EPERM` — the new namespace owns nothing |
| 4 | **Counter-arm:** put A and B in **one** netns; A binds an abstract name, B connects | **succeeds** — turns the shared-netns rendezvous from prediction into measurement |

Path 4 is the valuable one: it measures the thing the design relies on *not* being the case, which is the
only way the per-agent netns decision can be evidenced rather than asserted. Substrate caveat to check
first: unprivileged user-namespace creation may be restricted or absent on the WSL2 image, in which case
path 3 measures the image's policy rather than the kernel's rule.

---

## N5 · How does a network namespace actually die, and what does industry do about it?

**Second round, commissioned 2026-08-30 in the same session.** The first four questions asked whether a
namespace can be *entered*; this one asks how one *ends*.

**The kernel mechanism.** A network namespace is reference-counted. When the count reaches zero it is put
on a cleanup list drained by a **dedicated single-threaded workqueue** — the `netns` kernel thread running
`cleanup_net()`. Destruction is therefore **asynchronous and batched**: nothing "closes" a namespace, and
the moment the last reference goes away is not the moment the namespace ceases to exist.

Three properties of that mechanism matter here.

- **The gap between "no references" and "gone" is observable and can be long.** `cleanup_net` being slow is
  a recorded kernel problem, with reports of processes stalling on the order of a hundred seconds when
  many namespaces are torn down at once.
- **The reference counting itself has a bug history.** Over a hundred syzbot reports concerned a namespace
  being dismantled too early — a missing `get_net()` or an extra `put_net()` — which is why
  `CONFIG_NET_NS_REFCNT_TRACKER` was added to pair them precisely.
- **Nothing enumerates references for you.** A privileged process can find *process* references by walking
  `/proc/*/ns/net`, *descriptor* references by walking `/proc/*/fd/*` (those links render as
  `net:[inode]`), and *mount* references through the mount table — but there is no kernel interface that
  answers "who is holding this namespace".

**What industry does: the opposite of relying on the refcount.** In the Kubernetes/CNI flow the namespace
is created with `unshare(CLONE_NEWNET)` and then **deliberately pinned** by a bind mount under
`/var/run/netns/`, with a placeholder ("pause") container holding it for the pod's lifetime; teardown is an
**explicit** `CNI DEL` that releases addresses, interfaces and routes, followed by unmounting the pin,
after which the kernel reclaims it.

Two reasons drive that choice, and both are worth testing against any design that copies it: the namespace
must **outlive any single container**, because containers in a pod restart; and external programs (CNI
plugins are separate executables) need a **path-addressable handle** to enter the namespace and configure
it.

**The known cost of pinning is leakage.** A pin is a reference someone must remember to remove: moby issue
**#31414** records namespaces and interfaces left behind after every failed prestart hook, the CNI
specification requires `DEL` to succeed even when resources are already gone, and containerd has had to
change teardown so that a failing plugin does not block the rest of cleanup.

*Consequence for this design — stated as a fork, not a recommendation.* The design currently holds **no**
reference, so a namespace ends when the agent's last process does, asynchronously. Whether that is right
turns on two questions this survey cannot answer: whether an agent may ever restart while keeping its
identity, and whether any agent will need a real network path (which would require an external
configuration step, hence a handle). Both are design decisions.

---

## N6 · What are all the routes to a user namespace, and can seccomp close them?

**Answer: three routes, and seccomp can only filter two of them directly.**

| Route | Filterable by seccomp on the flag? |
|---|---|
| `unshare(CLONE_NEWUSER)` | Yes — the flag is a direct argument |
| `clone(CLONE_NEWUSER)` | Yes — same |
| **`clone3`** | **No** — its arguments live in a struct behind a pointer, and **seccomp cannot dereference pointers** |

The established remedy is not to block `clone3` but to make it return **`ENOSYS`**, which causes glibc to
fall back to `clone`, where the flag *is* filterable. Returning `EPERM` instead is a known failure: it
breaks thread creation outright, because glibc treats any errno other than `ENOSYS` as fatal. Both
containerd and Docker carry this as an explicit rule in their default profiles.

*Consequence:* a design requirement written as "deny `unshare`" closes one route of three. The complete
requirement is three clauses, and the third one is a specific errno, not a denial.

> **Ruled 2026-08-30 (user): all three clauses go in — and ROUTED the same day**, into spawn **step 11**
> of `option-b-workload-per-engine.md` and into the `S1` requirement
> row of `scope-and-boundary.md`, which had stated only the single
> deny-`unshare` clause. The `clone(CLONE_NEWUSER)` clause is carried there marked **not measured**.

---

## What N5 changes in the design files — one rule exists but names the wrong component

`mechanism.md` already carries the rule this section argues for: *"the engine must
**never pin** an agent's namespace (an fd or bind-mount on `/proc/<pid>/ns/*` keeps it alive after its
processes exit — how `ip netns` persists — and d6's teardown result would not hold)"*. The rule, its
reason and its lab evidence are all there. What is stale is the **subject**: the spawn and the reaping
duty moved to the spawner in 2026-08-17, and the rule was not moved with them.

> **Ruled 2026-08-30 (user): take the structural route — no reference is created, rather than references
> being hunted for — and ROUTED the same day** into `mechanism.md` §Identity lifecycle.
> The rule there now names **neither the engine nor the spawner**, adds the third prohibition it lacked
> (**no handle handed to anyone else**), and carries the kernel grounds: destruction is asynchronous
> (`cleanup_net`, a single-threaded workqueue) and no kernel interface answers *"who holds this
> namespace"*. **The paragraph above therefore describes the state before that edit.**

**Resolved 2026-09-01 — measured and promoted, no longer parked here.** The queued-message question raised
by reasoning on 2026-08-30 (credentials are stamped at send time, so a message still queued when the sender
dies carries the dead agent's uid; if that uid has been reissued, the engine reads the queued message
against the new session's row) was measured in N10's bundled arm and **holds**. It is now a `ROUTE-ITEM`
against `mechanism.md` §Identity lifecycle — a channel-teardown-before-uid-recycle ordering
requirement. Full statement and evidence: **N10, "Bundled arm."** This paragraph is the pointer, not a
second parking spot.

---

## N7 · Can a process change a namespace's configuration without the capability the kernel requires?

**Third round, commissioned and run 2026-09-01.** N1 asked whether an agent can *move into* someone
else's namespace. This asks the question N1–N6 never did: whether an agent can *change the contents* of a
namespace — add an interface, a route, a mount — without the capability the kernel demands for it.

**Answer: yes. It is published, it is recent, and — measured this session — the kernel this design pins is
on the vulnerable side of the fix.**

`CVE-2026-31692`, Linux CNA record, published 2026-04-30, quoted verbatim:

> "rtnetlink: add missing `netlink_ns_capable()` check for peer netns. `rtnl_newlink()` lacks a
> `CAP_NET_ADMIN` capability check on the peer network namespace when creating paired devices (veth,
> vxcan, netkit). This allows an unprivileged user with a user namespace to create interfaces in
> **arbitrary** network namespaces, including `init_net`."

This is stronger than the question asked. It is not "change your own namespace without the capability"; it
is **change *any* namespace without the capability**, including the host's.

**The provenance, because the dates carry the argument.** The flaw was introduced by `81adee47dfb6`
*("net: Support specifying the network namespace upon device creation", Eric W. Biederman, **2009-11-08**)*,
first released in 2.6.33. It was fixed by `7b735ef81286` (Nikolaos Gkarlis, **2026-04-02**), a 27-line
change to `net/core/rtnetlink.c` — so the check was absent from mainline between those two dates.

**Substrate posture — measured, and it is not academic.** The CNA record lists the fix present from
**6.18.24**, **6.19.14** and **7.0**, and records **no fixed version on the 6.6 branch** — where 6.6.x is
still in the affected range. (Mainline and the recent stable branches are fixed; the fix is not recorded
for this old LTS branch, and a WSL2 build is in any case a frozen Microsoft fork of it.) The lab substrate
is `6.6.87.2-microsoft-standard-WSL2`. The netns/userns cell's `base-peer` arm attempted exactly this — a
process in its own user namespace creating a veth whose peer end lands in a network namespace owned by the
initial user namespace, where it holds no `CAP_NET_ADMIN` — and **the kernel allowed it** (`rc 0`, device
created in the target, against a sacrificial namespace, cleaned afterwards). **So the missing-check
behaviour that `CVE-2026-31692` fixes is present on the pinned substrate** — measured against a sacrificial
namespace owned by the initial user namespace (the same ownership relationship as `init_net`), not against
`init_net` itself. Evidence:
`REPORT-netns-userns-rendezvous.md`
base-peer.

**What that does and does not mean for this design.** The precondition is an unprivileged **user**
namespace — the very thing spawn step 11 denies. So it does not breach the design as specified. What it
removes is the idea that the kernel offers a **backstop**: on this kernel there is no second line refusing
peer-netns configuration, so the whole guarantee rests on the seccomp deny of user-namespace creation
actually being installed. The realized profile is `SCMP_ACT_ALLOW` with 18 denials (`CRA-F21`), which is
why `S2` (default-deny) is load-bearing rather than tidy.

### A second case, in the adjacent door — and a handle route the primer does not have

`CVE-2026-43391`, Linux CNA record, published 2026-05-08:

> "nsfs: tighten permission checks for handle opening. Even privileged services should not necessarily be
> able to see other privileged service's namespaces so they can't leak information to each other."

The defect and its repair are one line, in `fs/nsfs.c`'s `nsfs_fh_to_dentry()`:

```c
-	if (owning_ns && !ns_capable(owning_ns, CAP_SYS_ADMIN)) {
+	if (owning_ns && !may_see_all_namespaces()) {
```

where the correct policy, read at `kernel/nscommon.c`, is **two** conditions, not one:

```c
bool may_see_all_namespaces(void)
{
	return (task_active_pid_ns(current) == &init_pid_ns) &&
	       ns_capable_noaudit(init_pid_ns.user_ns, CAP_SYS_ADMIN);
}
```

**Stated as a limit first, because the limit is what makes it honest: this one does not reach an
unprivileged agent.** Both the broken predicate and the correct one require `CAP_SYS_ADMIN`, and for a
sibling's namespace that means `CAP_SYS_ADMIN` in the **initial** user namespace, which an agent never
holds. The CVE's own words are "privileged services". It is evidence about a **class**, not about this
design's threat model.

**What it does change is the primer.** `kernel-namespace-primer.md` §2
states that `setns` accepts three kinds of handle — the `/proc/<pid>/ns/` magic links, bind mounts of
them, and pidfds since 5.8. There is now a **fourth**: `5222470b2fbb` *("nsfs: support file handles",
Christian Brauner, 2025-09-12, first released in 6.18)* makes namespaces addressable by
`open_by_handle_at()` file handle, explicitly so that a task need not have `/proc` mounted. That route
**shipped with the wrong permission gate and was corrected five months later.** It postdates the pinned
substrate — 6.6.87 has no nsfs file handles — so it is a forward-looking item, not a present one.

> **ROUTE-ITEM →** `kernel-namespace-primer.md` §2 · add the **fourth**
> handle kind (nsfs file handles, 6.18+) to the list of three, with the note that it is absent from the
> pinned substrate. The *Consequence* line already says descriptor hygiene must name pidfds; it must also
> say a namespace becomes addressable without `/proc` on kernels ≥ 6.18. **Held** — the primer is a design
> file; this is pinned, not written.

### The same defect shape, four years earlier

`CVE-2022-0492` — `cgroup_release_agent_write()` performed **no** privilege check at all; the fix (quoted
by Unit 42) added `if ((of->file->f_cred->user_ns != &init_user_ns) || !capable(CAP_SYS_ADMIN)) return
-EPERM;`. Note the shape: the repair is *"be in the initial namespace **and** hold the capability"* —
structurally identical to `may_see_all_namespaces()` above, arrived at independently four years apart.
Unit 42 also records that **seccomp denying `unshare` blocks the exploit**, because the container needs a
new user and cgroup namespace to obtain `CAP_SYS_ADMIN` in the first place — direct support for the
design's step-11 posture, from an exploit that actually worked.

### And the mitigation for the enabling step has its own bypass history

Every one of the above needs the same first move: an unprivileged user namespace. Ubuntu restricts that by
default from 23.10 via an AppArmor profile. In 2025 that restriction was bypassed three times — DEVCORE
(2025-06-26) documents its own bypass, which switches the process to a non-default unconfined profile so
that `aa_profile_ns_perm()`'s two-condition test never fires, and references earlier bypasses by @roddux
(2025-03-21) and Qualys (2025-03-27). DEVCORE's own summary is that *"bypassing it was not as difficult as
expected"*, and **no CVE was assigned** — Ubuntu classified it a variant.

*Consequence for this design, stated narrowly.* The design does not use AppArmor for this; it denies the
three syscall routes in seccomp (N6), so the bypasses do not transfer. What does transfer is the standing
qualifier from N4: **the deny is exactly as strong as the profile carrying it.** A policy-layer deny of
unprivileged user namespaces has now been publicly bypassed three times in one year; that is the empirical
case for `S2` being load-bearing rather than tidy.

---

## N8 · Has namespace isolation itself failed in the kernel — the mechanism, not its configuration?

~~**Answer: twice, both more than seven years ago, and only in two of the four namespaces — the user
namespace (`CVE-2018-18955`) and the pid namespace (`CVE-2009-1338`). In mount and network, nothing was
found.**~~ **Corrected 2026-09-07 (independent evidence rerun, user-approved): all four namespaces have a
mechanism-level defect history, and "nothing found" for mount and network was a database/writeup
non-discovery, not a fact.** Mount: `CVE-2015-4176` (commit `e0c9c0afd2fc` — a deletion could "trigger an
unmount and reveal data under a mount point" after a lazy detach) and `CVE-2014-9717` ("Honor `MNT_LOCKED`
when detaching mounts"), both fixed before 4.0.2. Network: RDS socket lookup ignored the network namespace
("Network namespaces are not part of the key", fix `5521ae71e32a`, merged July 2026) — the global-key lookup
is present in the pinned 6.6.87 source, but `CONFIG_RDS` is unset in the tagged WSL config. User: the map
write gate itself was repaired three times before `CVE-2018-18955` (`CVE-2013-1959`, `80dd00a23784`,
`db2e718a4798`). Pid: `CVE-2009-1338`. **What stands is narrower and still the claim the design needs: none
of these reaches its specific reliance** — `pivot_root` + `MNT_DETACH` from a private tmpfs root, and a
per-agent netns closing AF_UNIX abstract-name / loopback rendezvous (RDS is a different socket family). The
filter below still does its job — it sets the caller-class and reachable-code-class look-alikes aside — but
the count it produced was wrong. Getting *to* it needed a filter, because most CVEs filed under "namespace
broken" are not the mechanism failing — the table below sets the look-alikes aside so the count means what
it says; it is the filter that produced the answer, not the answer itself.

| Shape | What actually failed | Cases found |
|---|---|---|
| **1. The namespace mechanism returned a wrong answer** | the isolation logic itself | **user** — `CVE-2018-18955` (+ the earlier write-gate repairs `CVE-2013-1959` / `80dd00a23784` / `db2e718a4798`); **pid** — `CVE-2009-1338`; **mount** — `CVE-2015-4176`, `CVE-2014-9717` (corrected 2026-09-07); **net** — RDS cross-netns delivery, fix `5521ae71e32a` (corrected 2026-09-07) |
| **2. A caller checked capability against the wrong namespace, or not at all** | the *users* of the mechanism | `CVE-2022-0492`, `CVE-2026-31692`, `CVE-2026-43391` — this is N7's class, and it is still live |
| **3. Memory-safety bugs in code merely *reachable* through a namespace** | the kernel, elsewhere | `CVE-2022-0185`, the `nf_tables` corpus, `CVE-2024-53095` — isolation held; the kernel underneath did not |

Only shape 1 answers the question as asked. Shape 3 is N4's territory, which the design already places in
the out-of-scope residual.

**User namespace — `CVE-2018-18955`, and it lands on this design's identity half.** The fix commit
`d2f007dbe7e4` (Jann Horn, 2018-11-05, `kernel/user_namespace.c`, **+8 −4**) states the defect in its own
words:

> "The current logic first clones the extent array and sorts both copies, then maps the lower IDs of the
> forward mapping into the lower namespace, **but doesn't map the lower IDs of the reverse mapping**. This
> means that code in a nested user namespace with >5 extents will see **incorrect IDs**. It also breaks
> some access checks, like `inode_owner_or_capable()` and `privileged_wrt_inode_uidgid()`, so a process
> can **incorrectly appear to be capable** relative to an inode. … This is CVE-2018-18955."

This is the id-translation machinery — the exact mechanism
`kernel-uid-binding.md` §3 rests on — giving wrong answers, and capability checks
being wrong as a direct consequence. It is not a missing check in a caller; it is the mechanism itself.
Introduced by `6397fac4915a` *("userns: bump idmap limits to 340", Christian Brauner, 2017-10-24)*, which
added the >5-extent sorted path; fixed **12.5 months later**, in 4.19.2.

**Pid namespace — `CVE-2009-1338`.** Linux CNA record, verbatim: *"The `kill_something_info` function in
`kernel/signal.c` … does not consider PID namespaces when processing signals directed to PID -1, which
allows local users to **bypass the intended namespace isolation**, and send arbitrary signals to all
processes in all namespaces."* Fixed before 2.6.28 — roughly a year after pid namespaces shipped in
2.6.24.

**Mount and network — ~~null results~~ the null did not survive re-search (2026-09-07).** The first search
(vulnerability databases + vendor writeups: mount escape / propagation; veth / bridge leakage; `struct net`
misuse) returned only shape-2 and shape-3 cases, and the limit stated at the time — *not a systematic
audit* — turned out to be the whole story: kernel-git history and primary fix commits found the mechanism
cases now listed in the table. The corrected statement is not "mount and net never failed" but **"the
failures found do not reach this design's construction"** — which is the only claim the design needs.

**Completeness backstop, 2026-09-08.** The audited supplement adds
individual dispositions for 116 CVE candidates and 1,546 unique commits / 1,707 path-history rows. Its
mount- and AF_UNIX-adjacent priority candidates remain shape 2, shape 3, or applicability-unknown; none is
a new shape-1 break reaching `pivot_root` + `MNT_DETACH` from the private root or per-agent AF_UNIX/netns
scoping. The ledger-level result strengthens the audit trail without changing N8's corrected answer.

### The peer-reviewed positive check — ACSAC 2018 (a bounded experiment, not a census)

Lin, Lei, Wang, Jing, Sun and Zhou, *A Measurement Study on Linux Container Security: Attacks and
Countermeasures*, **ACSAC 2018**, pp. 418–429, collected **223 exploits** effective on container
platforms and executed **88** of them; **50 (56.82 %)** worked from inside a container with Docker's
default configuration. Of the 37 privilege-escalation exploits, **11 broke container isolation and
obtained root** (4 under Docker's default profile, 7 only with `CAP_NET_ADMIN` added — §5.1, p.425; §5.3
evaluates all 11 with that capability enabled) — and the paper's finding about those 11 is the answer to
this section:

> "By analyzing the 11 exploits, we find they follow a common **4-step attack model** … First, they bypass
> (or manually disable) the KASLR mechanism … Second, they exploit the kernel vulnerabilities such as UAF,
> race condition, improper verification, buffer overflow etc., to enable the overwriting of the pointers
> of some kernel functions … Third, they overwrite these kernel functions' pointers so that … the
> SMEP&SMAP mechanisms will be disabled … Finally … invokes the kernel function `commit_creds()` to apply
> for ROOT credential."

**Not one of the four steps touches a namespace.** Every exploit that escaped did so by compromising the
kernel and then rewriting the process credential. The paper's own limitations section names the namespace
sequel explicitly: *"attackers might invoke the `switch_task_namespaces()` method to achieve container
escape"* — i.e. once the kernel is owned, `nsproxy` is a pointer like any other, and the namespace is not
defeated on its own terms but bypassed underneath.

**The same paper also measures the design's own layering, and does not flatter it.** *"the kernel security
mechanisms such as Capability, Seccomp and MAC play a more important role in preventing privilege
escalation attacks than the container isolating mechanisms (i.e., Namespace and Cgroup). The former blocks
67.57 % privilege escalation attacks while the later blocks only 21.62 %."* Reported as found — **with the paper's own baseline attached (2026-09-07): the 67.57 % / 21.62 % split is
computed with `CAP_NET_ADMIN` enabled for the 7 exploits that needed it, so it is conditional on that
relaxed-capability setting and is not a default-Docker rate** — for **privilege escalation**, namespaces
are the junior partner. That is consistent with this design, which
does not ask namespaces to prevent escalation — it asks them to close *reachability*, and asks the
capability posture and seccomp to close escalation. But the sentence must not be quoted as support for
namespaces; it is a boundary on what they buy.

**And where namespaces did block, they blocked in exactly this design's way.** The paper records that the
mount namespace blocked exploits using `CVE-2016-5195` (Dirty COW) and `CVE-2016-4557` — not by
intercepting them, but because *"processes isolated by the mnt namespace can only modify the files inside
the namespace, thus are not able to modify the real target files on the host"* — and that the network
namespace blocked `CVE-2017-14489` and `CVE-2017-16939`, which *"require NETLINK to communicate with Linux
kernel"*. That is the construction property this design claims, measured by a third party on real
exploits: **the target had no name the process could reach.**

---

## N9 · Were those design defects or implementation defects — and what may the thesis therefore say?

**Answer: the enforcement failures are implementation defects and the repair record is unambiguous about
it; but the unprivileged user namespace is treated by everyone downstream as a *design* problem, and the
thesis has to say the two things separately.**

**The repair record, by size.** Every case above was fixed in place, without altering the namespace model:

| Case | Repair | Size |
|---|---|---|
| `CVE-2009-1338` | consider the pid namespace when signalling pid −1 | point fix in `kernel/signal.c` |
| `CVE-2018-18955` | also translate the reverse map, and sort it *after* translating | `kernel/user_namespace.c` **+8 −4** |
| `CVE-2022-0492` | require init user namespace **and** `CAP_SYS_ADMIN` | one added condition |
| `CVE-2026-31692` | add the missing `netlink_ns_capable()` on the peer netns | `net/core/rtnetlink.c` **+27 −13** |
| `CVE-2026-43391` | swap the wrong predicate for `may_see_all_namespaces()` | `fs/nsfs.c` **+1 −1** |

No case required a model change, a new abstraction, or a deprecation. Three of the five are the *same*
defect — a capability check evaluated against the wrong namespace, or missing — and two of those three
were repaired with the identical two-condition idiom (*be in the initial namespace and hold the
capability*) arrived at independently in 2022 and 2026. **A recurring implementation defect with a known
repair idiom is the signature of an implementation problem, not a design one.**

**The counterweight, which is not small.** The *unprivileged user namespace* — the enabling first step of
every shape-2 case — is not treated as an implementation defect by anyone. The responses are all wholesale
restrictions of the feature, which is what you do to a design decision you cannot repair:

- Ubuntu restricts it by default from 23.10 through an AppArmor profile — a distro disabling a kernel
  feature, not fixing it.
- Solar Designer, on oss-security (2024), argues for `user.max_net_namespaces=0`, quoting Apptainer:
  *"There have been many Linux kernel exploits that have made use of unprivileged user namespaces as a
  point of entry, but almost all of them in the last few years have been in combination with network
  namespaces."*
- Meng, Wang, Lei, Kou, Wang and Lu, ACISP 2025, propose adding a capability check *before* user
  namespace creation — again a restriction on the feature, not a repair of a bug.

**What the thesis may therefore say — three sentences, and the third is the one that is easy to get
wrong.** (1) The namespace *isolation mechanisms* this design relies on have a defect history that is
short, old, confined to two of the four namespaces, and repaired by local point fixes — the thesis may
say the mechanism **can be relied on**, with the evidence named. (2) The *callers* of those mechanisms have
a live and recurring defect history, one instance of which is unfixed on the
pinned substrate (measured, N7) — so the thesis may **not** extend that reliance from the mechanism to
everything that configures it. (3) The **user namespace is not a boundary and this is a settled community position,
not a discovery of this survey**; the design already agrees, which is why it denies creation — but that
means the honest claim is *"the design does not rely on the user namespace being a boundary"*, never *"the
user namespace holds."*

> **ROUTE-ITEM →** `kernel-derivations.md`, the substrate row that carries the
> *"43 % of user-namespace-gated CVEs are in `nf_tables`"* restriction (N4, open) · the figure now has a
> **peer-reviewed replacement that does not depend on the vendor article**: Meng et al., ACISP 2025,
> report **32 of 51 analysed exploits escalated privilege by creating a new user namespace**, with a
> prototype on Linux v6.6.3 — the same 6.6 series as the pinned substrate. Restate the claim with this
> number and retire the vendor concentration figure. **Verification level: the 32/51 and the v6.6.3
> figures are read from the publisher's abstract; the chapter itself is paywalled and unread.** Citation
> metadata is CrossRef-confirmed (Sources). Note also that Lei and Wang are authors on both this and the
> ACSAC 2018 study, so the two are not fully independent groups. **Held** until plan step 2 rewrites that
> section.

---

## N10 · Can two agents meet by creating or joining the same user namespace?

**Both halves are answered: the literature found the gap the question predicted, and the cell measured
it.** The chain closes on the per-agent uid.

### The three walls, each sourced

1. **`unshare` always makes a new namespace, never joins one.** `unshare(CLONE_NEWUSER)` creates; only
   `setns` joins (`kernel-namespace-primer.md` §2, man-pages).
2. **Joining needs `CAP_SYS_ADMIN` in the target.** `user_namespaces(7)`, verbatim: *"A single-threaded
   process can join another user namespace with `setns(2)` if it has the `CAP_SYS_ADMIN` in that
   namespace; upon doing so, it gains a full set of capabilities in that namespace."*
3. **Capabilities descend; they do not cross.** Kerrisk, *Namespaces in operation, part 6*: a process in
   one child user namespace cannot switch to a sibling because *"that namespace is not an ancestor … Thus,
   the child process does not have the `CAP_SYS_ADMIN` capability in that namespace."*

### The rule none of the three mentions, and it is the gap

`user_namespaces(7)`, verbatim:

> "When a user namespace is created, the kernel records the **effective user ID of the creating process**
> as being the **'owner'** of the namespace. A process that resides in the **parent** of the user
> namespace and **whose effective user ID matches the owner** of the namespace **has all capabilities in
> the namespace**."

Kerrisk states the consequence outright: *"after creation of a new user namespace, other processes owned
by the same user in the parent namespace have all capabilities in the new namespace."*

**So wall 2 is not a capability wall. It is a *uid comparison*.** "Does B hold `CAP_SYS_ADMIN` in A's user
namespace?" reduces, for a process still in the parent namespace, to "**is B's euid equal to A's**".

### Measured — arms 2 and 3 differ in one variable, and it is the uid

The cell `netns_userns_rendezvous_probe.py` ran the chain on the pinned substrate (2026-09-01,
`REPORT-netns-userns-rendezvous.md`).
Agent A, at uid 1001, created a user namespace it owns, a netns inside it, and bound an abstract name
there.

| Arm | B's uid | B's starting user ns | `setns` → A's userns | then A's netns | rendezvous |
|---|---|---|---|---|---|
| 1 | 1002 | its **own** (a sibling of A's) | `EPERM` | — | — |
| 2 | 1002 | the **initial** | `EPERM` | — | — |
| 3 | **1001** | the **initial** | **SUCCESS** (uid 0, full caps in A's userns) | **SUCCESS** | **CONNECTED** |

**Arm 2 and arm 3 changed exactly one thing — B's uid — and the wall opened.** On success B's credentials
inside A's user namespace read uid 0, `CapEff` `000001ffffffffff`; it then entered A's inner netns and
connected to the abstract name that has no permission check. Arm 1 confirms the sibling wall from
`netns_entry_probe.py` is not circumvented: once B makes its *own* user namespace it is A's sibling,
capabilities descend but do not cross, and `setns` returns `EPERM` even at the matching uid, because the
owner rule requires B to be in the **parent** of A's namespace and a sibling is not.

### The chain, and what it does and does not breach

If agent A creates a user namespace of its own — which is what the seccomp deny of N6 exists to prevent —
then `U_A`'s owner is A's uid; a sibling B **still in the initial user namespace with the same uid** holds
all capabilities in `U_A`; B may `setns` in and gains a full set; every namespace A made *inside* `U_A` is
owned by `U_A`, so B satisfies both `setns` conditions for those too; and the two now share a netns where
an abstract socket has no permission check.

**It does *not* open the namespaces the spawner made** — those are owned by the initial user namespace,
where neither agent holds anything (`netns_entry_probe.py` paths 1–3, unchanged). What the chain builds is
a **new meeting room of the agents' own construction**, reached without touching anything the spawner
created.

**This route is closed twice, independently — and that is how the finding should be read.** The seccomp
deny of N6 stops the user namespace being created at all (the first lock); and even without it, distinct
per-agent uids stop the rendezvous (the second lock, measured — arm 3 succeeds only because B shares A's
uid, and this design allocates **one uid per agent**, so arm 2 is the real configuration and it is
refused). So this is **defense in depth**, not a live hole that depends on the chain never running.

What it changes **unconditionally** — true whether or not the deny holds — is the argument's structure:
`kernel-namespace-confinement.md` §6 attributed the sibling wall
entirely to the owning-user-namespace rule and **did not state that the rule's premise is uid
distinctness**, so the reachability argument carries an unstated dependency on the identity argument. (The
map-write mechanics that make "become or register another agent's uid" impossible live in
`kernel-uid-binding.md` §3 and the primer §7 — **measured 2026-09-03** (the
`forge-map` / `forge-setuid` arms: writing a foreign uid → `EPERM`, `setuid` to one → `EINVAL`); they are
not re-derived here.)

**It is the second time the same pairing has appeared.** In `CVE-2020-15257` (N3) a peer-credential check
was worthless because two principals shared a uid; here a namespace wall is worthless for the same reason.
Two independent mechanisms, one shared precondition: **distinct per-agent uids are load-bearing twice, and
the design credits them once.**

**Folded into the derivation this session:**
`kernel-namespace-confinement.md` §6 now carries §6.1, which states the
rendezvous composition and its uid dependency (confinement is an `L1` derivation, not a design file, and
step 6 of the parent plan folds survey conclusions into it).

> **ROUTE-ITEM →** `scope-and-boundary.md` §Boundary Defence · the design-file
> consequence: per-agent uid allocation is load-bearing for the **reachability** boundary, not only the
> identity boundary — an agent that obtains its own user namespace can rendezvous with any sibling at the
> same uid (measured 2026-09-01, arms 2-vs-3). State it where the per-agent-uid decision is registered.
> **Held** until plan step 2 (`S2` + W2) rewrites that section, alongside the abstract-socket item already
> pinned in `kernel-derivations.md`.

### Has anyone written the composition down?

**Null result.** Each of the three walls and the owner rule is documented — man-pages and Kerrisk's LWN
series state all four plainly. **No source was found that composes them**, i.e. that asks whether two
unprivileged sibling processes can rendezvous through a user namespace one of them creates, or that
identifies uid distinctness as the term that closes it. The searches returned the constituent rules and
container-escape material, never the composition. **Limit:** this is a search null over public literature,
not a systematic review.

### Bundled arm — the queued message carries the dead sender's uid

The `qmsg` arm resolves N5's parked open question. A datagram sender set uid 1001, sent, exited, and was
**reaped before the receiver read** (`/proc/<pid>` gone at read time); the `SCM_CREDENTIALS` that arrived
still read **uid 1001**. Credentials are stamped into the skb at send time and travel with the queued
message; they are not re-derived at receive time. So the claim N5 was reasoning about with no measurement
**holds**: a message read after its sender's death carries the dead agent's uid, and if that uid has been
returned to the pool and reissued, the engine would read the queued message against the **new** session's
row.

> **ROUTE-ITEM →** `mechanism.md` §Identity lifecycle · the reclamation ordering must
> include *"drain or close the agent's channel before its uid returns to the allocation pool"*, because a
> queued message outlives the sender and carries the sender's stamped uid (measured 2026-09-01, `qmsg`
> arm). This is an **ordering** requirement between channel teardown and uid recycling, adjacent to the
> existing "no pinned namespace" rule. **Held** — `mechanism.md` is a design file.

---

## What (b) and (d) come to — the two questions this round exists to answer

**(b) — can an agent change the content of the namespace it was given?**

**No.** The fact that answers the question you would ask next: **the agent's own namespaces and every
sibling's are all owned by the same (initial) user namespace** — the spawner created them there. So
*administrative authority* over a namespace is identical for the agent's own and a sibling's: it has it over
**neither**, not even its own. The only thing that differs is *membership* — the agent was placed in its
own and cannot join a sibling's. Creating a user namespace of its own changes nothing: that makes it root
over what *it* creates, never over what it was handed. So the answer to (b) is **ownership**, not the
seccomp deny.

The full picture, path by path (measured at the step-11 posture); note that only the last lock is *not* the
kernel's:

| If the agent tries to… | It is stopped by | The lock |
|---|---|---|
| reconfigure the namespace it was given (even bring up `lo`) | no `CAP_NET_ADMIN` in the owning (initial) user ns — it has authority over none of its own namespaces; the spawner raises `lo` *before* the drop (base-cfg, measured) | ownership (structural) |
| create a user namespace of its own — the gate to every row below | the seccomp deny (N6, three clauses), today in a **default-allow** profile (`CRA-F21`) — which is why `S2` is load-bearing | filter (`S2`) |
| enter a sibling's namespace via `setns` | `setns` needs `CAP_SYS_ADMIN` in the sibling's owning (initial) user ns — it has none; membership can only be gained here, and this is the gate | capability |
| rendezvous with a sibling through a shared user ns | the owner rule needs an **equal uid** — per-agent allocation denies it (N10) | identity (uid) |
| inject into another netns via `CVE-2026-31692` | it cannot **name** a target netns — no foreign pid is visible from its own pid namespace, and it holds no handle to one | **referencing isolation — *not* the kernel** |

**The last row is the only honest edge.** The kernel's own peer-netns check is *missing* on 6.6.87 (N7), so
nothing there refuses the injection — the sole barrier is that the agent can name no target. A single leaked
netns handle (a pidfd included, N1) would remove it, which is what makes descriptor hygiene load-bearing
rather than tidy. Everywhere else the lock is structural (ownership), a capability the agent lacks, or the
per-agent uid.

**(d) — has namespace isolation been broken in the kernel, and how far may the thesis rely on it?**

~~**Yes, but only twice — both more than seven years ago, both only in the user and pid namespaces; in mount
and network, never.**~~ **Corrected 2026-09-07 (independent evidence rerun, user-approved): yes, in all
four namespaces — and none of the cases reaches what this design relies on.** User: the reverse id-map
defect `CVE-2018-18955` (2018) plus three earlier repairs of the map *write gate* itself; pid:
`CVE-2009-1338` (pre-2.6.28); mount: `CVE-2015-4176` and `CVE-2014-9717` (detach / locked-mount
connectivity, fixed before 4.0.2); network: RDS delivery ignoring the netns (fixed July 2026; code present
on the pin, `CONFIG_RDS` unset in the WSL config). Every one was repaired in place, without a model change
— but "few, old, two namespaces" was a count produced by an incomplete search, and it is retired.

**So the thesis may rely on the mechanism — in a bounded, evidenced way, with the bound stated honestly.**
The evidenced statement is: *within a logged search of kernel history, primary fix commits, syzbot and the
academic record, no published case breaks the specific construction this design uses — `pivot_root` +
`MNT_DETACH` from a private tmpfs root, and a per-agent netns closing AF_UNIX abstract-name and loopback
rendezvous.* The strongest external check, ACSAC 2018, ran 11 exploits that broke container isolation (4
under the default profile, 7 with `CAP_NET_ADMIN` added) and found **all 11** worked by compromising the
kernel and rewriting `commit_creds()` — **none** defeated a namespace on its own terms. The escapes that
actually happen go *under* the namespace, not *through* it. That is a positive, bounded experiment, not a
census: it does not exclude the mechanism defects above, and it does not license the word "never".

Two limits bound that reliance and may not be dropped:

- **It is the mechanism that can be relied on, not the code that configures it.** The live, recurring
  failures are in the *callers* — a capability check missing or scoped to the wrong namespace — three
  between 2022 and 2026, one (`CVE-2026-31692`) measured present on our substrate. The isolation logic
  holds; the configuration code around it does not, and the thesis must not let one stand in for the other.
- **It is a construction property, not protection against a compromised kernel.** Once the kernel is owned,
  `nsproxy` is a pointer and `switch_task_namespaces()` a function — the namespace is bypassed underneath,
  not defeated. That is the out-of-scope residual, not a counter-example.

**So: the mechanism can be relied on as a construction — its defect history is real in all four
namespaces, always repaired in place, and none of it reaches this design's specific construction within
the logged search — but never against an attacker already inside the kernel, never as a blanket property of
everything that touches a namespace, and never as "it has not been broken".**

---

## Status note — what ran and what is pinned (2026-09-01)

All four questions were searched separately (a combined prompt was refused by a safety classifier on
2026-08-30, per the plan). Mid-session the harness's auto-mode safety classifier began refusing file
writes, reporting it was reacting to accumulated conversation content rather than to any action; the
session switched to the default permission mode, after which the cell was written, run, and its results
folded in here. **Nothing in this survey is routed into a design file**; the four `ROUTE-ITEM` blocks
above are pinned beside the content they govern, all marked **Held** until the parent plan's step 2
rewrites the sections they touch.

---

## Sources — every claim above traces to one of these

**Round one (N1–N4).**

- `setns(2)`, man-pages — permission rule, accepted descriptor kinds (including pidfd since 5.8).
  <https://man7.org/linux/man-pages/man2/setns.2.html>
- `user_namespaces(7)`, man-pages — full capability set on joining a user namespace.
  <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>
- `ip-netns(8)`, man-pages — bind-mount persistence of a network namespace.
  <https://man7.org/linux/man-pages/man8/ip-netns.8.html>
- NCC Group, *ABSTRACT SHIMMER (CVE-2020-15257): Host Networking is root-Equivalent, Again*, 2020-12-10.
  <https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/>
- oss-security announcement, *CVE-2020-15257: containerd-shim API exposed to host network containers*.
  <https://seclists.org/oss-sec/2020/q4/174>
- moby issue #31414 — leaked network namespaces and interfaces after failed prestart hooks.
  <https://github.com/moby/moby/issues/31414>
- Edera, *Linux User Namespaces: 262% More Kernel Attack Surface* — chain and `nf_tables` concentration;
  **headline multiplier not citable**. <https://edera.dev/stories/user-namespaces-are-not-a-security-boundary>
- Aalto University thesis, *Security Risks for Sidecar Containers in Kubernetes* — shared-netns sidecar
  isolation as an open problem.
  <https://aaltodoc.aalto.fi/server/api/core/bitstreams/afda5fe4-edbe-43bb-996f-92ff0a663977/content>

**Round two (N5–N6).**

- LKML, *net: cleanup_net is slow*. <https://lkml.iu.edu/hypermail/linux/kernel/1704.2/04491.html>
- LWN, *net: netns refcount tracking series* — the syzbot history and `CONFIG_NET_NS_REFCNT_TRACKER`.
  <https://lwn.net/Articles/877939/>
- CNI specification — `DEL` semantics and idempotence requirement.
  <https://github.com/containernetworking/cni/blob/main/SPEC.md>
- containerd PR #10800 — teardown failure must not block cleanup.
  <https://github.com/containerd/containerd/pull/10800>
- LWN, *clone3() + seccomp = bad*. <https://lwn.net/Articles/1035182/>
- containerd PR #6013 — `clone3` returns `ENOSYS` unless `CAP_SYS_ADMIN` is granted.
  <https://github.com/containerd/containerd/pull/6013>
- moby #42680 — blocking `clone3` with `EPERM` breaks glibc.
  <https://github.com/moby/moby/issues/42680>

**Round three (N7–N10, 2026-09-01).** CVE descriptions quoted from the Linux-CNA records via the MITRE CVE
Services API (`cveawg.mitre.org/api/cve/<id>`); commit messages, diffstats, and introducing-commit dates
read from the kernel git history via the GitHub mirror (`api.github.com/repos/torvalds/linux/commits/<sha>`).

- `CVE-2026-31692` — *rtnetlink: add missing `netlink_ns_capable()` check for peer netns*. Fix commit
  `7b735ef81286` (Nikolaos Gkarlis, 2026-04-02, `net/core/rtnetlink.c` +27 −13); introduced by
  `81adee47dfb6` (Eric W. Biederman, 2009-11-08). Affected 2.6.33 → before 6.18.24 / 6.19.14 / 7.0; **no
  fix on the 6.6 branch** as the record stands. <https://cveawg.mitre.org/api/cve/CVE-2026-31692>
- `CVE-2026-43391` — *nsfs: tighten permission checks for handle opening*. Fix `d2324a9317f0` / backport
  `1797ee11451f` (Christian Brauner, `fs/nsfs.c` +1 −1); the correct policy is `may_see_all_namespaces()`
  in `kernel/nscommon.c`. Introduced by `5222470b2fbb` *("nsfs: support file handles", 2025-09-12)*;
  affected 6.18 → 6.19.9. <https://cveawg.mitre.org/api/cve/CVE-2026-43391>
- `CVE-2018-18955` — *userns: also map extents in the reverse map to kernel IDs*. Fix `d2f007dbe7e4` (Jann
  Horn, 2018-11-05, `kernel/user_namespace.c` +8 −4); introduced by `6397fac4915a` *("userns: bump idmap
  limits to 340", 2017-10-24)*; fixed in 4.19.2.
  <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d2f007dbe7e4>
- `CVE-2009-1338` — `kill_something_info` does not consider PID namespaces for pid −1; fixed before 2.6.28.
  <https://cveawg.mitre.org/api/cve/CVE-2009-1338>
- `CVE-2022-0492` — `cgroup_release_agent_write` missing `CAP_SYS_ADMIN` check; the fix requires init user
  namespace **and** the capability. Root-cause and seccomp-blocks-it analysis: Palo Alto Unit 42.
  <https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/>
- Lin, Lei, Wang, Jing, Sun, Zhou — *A Measurement Study on Linux Container Security: Attacks and
  Countermeasures*, ACSAC 2018, pp. 418–429. The 223/88/50 dataset, the 11 isolation-breaking exploits,
  the 4-step model, and the 67.57 %-vs-21.62 % split. DOI 10.1145/3274694.3274720; PDF read at
  <https://csis.gmu.edu/ksun/publications/container-acsac18.pdf>.
- Meng, Wang, Lei, Kou, Wang, Lu — *Mitigating the Unprivileged User Namespaces Based Privilege Escalation
  Attacks with Linux Capabilities*, ACISP 2025, LNCS pp. 329–347. 32-of-51 figure and the v6.6.3 prototype
  **read from the publisher abstract; chapter paywalled and unread**. DOI 10.1007/978-981-96-9101-2_17.
- `user_namespaces(7)`, man-pages — the owner rule (effective uid of the creator; a same-uid process in
  the parent has all capabilities). <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>
- Kerrisk, *Namespaces in operation, part 6: more on user namespaces*, LWN — owner rule, `setns` into a
  user namespace, and why a sibling cannot cross. <https://lwn.net/Articles/540087/>
- Solar Designer et al., oss-security, *Disabling network namespaces* (2024) — `user.max_net_namespaces=0`
  and the Apptainer quotation. <https://seclists.org/oss-sec/2024/q2/133>
- DEVCORE, *The Journey of Bypassing Ubuntu's Unprivileged Namespace Restriction* (2025-06-26) — the
  AppArmor bypass, and pointers to the @roddux and Qualys bypasses.
  <https://devco.re/blog/2025/06/26/the-journey-of-bypassing-ubuntus-unprivileged-namespace-restriction-en/>
- Measurement: `netns_userns_rendezvous_probe.py` + `REPORT-netns-userns-rendezvous.md` (this repo,
  2026-09-01) — the rendezvous chain (arms 1–3), the `CVE-2026-31692` missing-check behaviour measured
  present in base-peer, and the
  queued-message uid arm.
