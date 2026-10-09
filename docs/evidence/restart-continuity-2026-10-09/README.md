# Local restart-continuity evidence

These finite tests ran on a disposable OrbStack Linux environment and a
capability-only kind deployment. `results.json` records the kernel, runtime,
image, observation intervals, counts, checkpoint coverage, and boundaries.
The rolling TCP streams and all four new-Pod guard streams are retained here
without changing their packet counts.

Validate the TCP, kernel-counter, compatible-upgrade, and uninstall records with:

```sh
go run ./tools/phase5verify -restart-dir=docs/evidence/restart-continuity-2026-10-09
```

`linux-integration.txt` records the race-enabled privileged `make integration`
run. The seventeenth subject checkpoint, added afterward, passed separately in
`linux-cleanup-checkpoint.txt`. `linux-bootstrap.txt` records the final real
cgroup bootstrap test, including rejection of a live static Pod whose API
status lacks a complete container identity. The full suite also covers three
parent-guard upgrade checkpoints, incomplete committed identities, cgroup
replacement, capacity and partial-pinning failures, cleanup, locking, and flow
reader reconnection.

Final `make check`, Linux lint, generated-binding reproducibility, capability
checks, and the bundle verifier passed. Uninstall was rerun on the final test
image before removing the owned cluster, containers, and VM. The remote CI run,
full hosted performance fixture, and reboot continuity were not executed by
these local tests. Initial installation and migration still require a workload
traffic gate or drained workloads; outage enforcement uses the last committed
snapshot within the current kernel boot.
