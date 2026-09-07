# BF2 QER regression test

This standalone test compiles the repository's real `onvm/upf/hw_offload_msg.h`
and extracts the three QER selection/stamping helpers directly from
`5gc/upf_c/upf_hw_offload.h`. It uses small type and list stubs solely to avoid
DPDK, DOCA, and the full UPF build.

From the repository root, run:

```sh
bash tests/run_bf2_qer_regression.sh
```

The test asserts the 104-byte wire ABI and `hw_qer_id` offset 96, then covers
GBR flow identity/rates, shared session identity for non-GBR PDRs,
direction-specific session selection, distinct supplied identities across
sessions, missing-session fallback, removal-style zero output, and no-QER
behavior. A source-layout change that prevents exact helper extraction fails
the runner explicitly.

Requirements: Bash, awk, sed, grep, a C11 compiler and standard libc headers.
No DOCA/DPDK SDK, root privileges or live traffic are required. An optional
first argument selects another repository root. Temporary build files are
removed on exit; a failed assertion or extraction produces a nonzero status.

The cross-session case supplies different hardware identities with the same
PFCP QER ID; it tests selection/stamping, not the atomic identity allocator.
The test does not execute the full PFCP handler, asynchronous Comch transport,
hardware programming or live QER migration. Session-QER selection retains the
implementation's assumption that the largest non-GBR maximum is the session
limit. Full integration also requires rebuilding host-agent and UPF-C against
the matching DPU wire layout.
