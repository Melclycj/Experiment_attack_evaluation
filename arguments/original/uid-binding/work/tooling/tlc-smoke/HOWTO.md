# TLC smoke check (verified 2026-10-12 on this machine)

Toolchain: Java 21.0.6 (Oracle, on PATH) and the official TLA+ tools jar downloaded from the
tlaplus/tlaplus GitHub "latest" release to `<tlaplus-dir>\tla2tools.jar` (2,274,532 bytes,
outside the repository). No Toolbox IDE is needed; TLC runs from the command line.

`Smoke.tla` is a three-variable toy of the uid reclamation double gate: `Reclaim` needs both
`rowClosed` and `nsEmpty`; `BadReclaim` needs only `nsEmpty`. `Inv` says a reused uid implies both gates.

```
cd <this folder>
java -cp <tlaplus-dir>\tla2tools.jar tlc2.TLC -config Smoke.cfg Smoke.tla
java -cp <tlaplus-dir>\tla2tools.jar tlc2.TLC -config SmokeBad.cfg Smoke.tla
```

Observed 2026-10-12: first run "Model checking completed. No error has been found." (7 states generated,
5 distinct); second run "Error: Invariant Inv is violated." with a counterexample trace. This only shows the
tool runs here and reports counterexamples; it is not a result about the design.
