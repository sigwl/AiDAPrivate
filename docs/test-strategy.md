# AiDA Test Strategy

Phase 1 lane D. Test tiers promote from lowest side effect to highest. A tier may be run only when its prerequisites are present and its evidence contract is satisfied. Missing prerequisites are reported as `missing` or `dependency_blocked`, not converted into feature failures.

## Global Rules

- Use the controlled `AiDA_TestTarget.exe` for target-process tests. Do not substitute an arbitrary process unless the test explicitly requires it.
- Treat `aida_full_test.log` as the Test Lab run record. For standalone runtime, MCP, browser, or driver failures, retain `aida_debug.log`; retain `C:\Users\Public\Desktop\aida_kernel.log` for kernel evidence.
- Every result must distinguish `passed`, `failed`, `missing`, `timed_out`, `crashed`, `cancelled`, `malformed_result`, and `integrity_failure` where the runner supports those outcomes.
- Cancellation is cooperative. It prevents subsequent work from starting; an in-flight synchronous low-level operation may return before ownership and cleanup state are released.
- Do not load WhosWho casually. Driver-backed tiers require an intentional research host or VM, explicit operator authorization, and evidence that target attach and cleanup completed. A driver load failure is a prerequisite result, not proof of a feature regression.
- Preserve Win32 message-pump invariants during every UI or live integration run: `kAidaQueuedPeekFlags` includes `PM_QS_SENDMESSAGE`; send-only work drains with `PM_REMOVE | PM_QS_SENDMESSAGE`; the empty-queue path still performs a nonblocking `PeekMessage` probe.

## Tier Matrix

| Tier | Scope | Promotion gate |
| --- | --- | --- |
| 1. Pure/headless | Parser proof, safe-headless contracts, deterministic code that neither launches a target nor requires network, driver, browser, or live operation | All assertions pass; result envelope, identity, ledger, and bounded resource contract validate; no cancellation or cleanup gaps |
| 2. Local process fixture | `AiDA_TestTarget.exe`, target protocol fixture, target memory/thread/module/debug surfaces | Target launches and reaches `READY`; PID/TID and fixture evidence are valid; dependent tests do not run when launch or attach prerequisites fail; target exits through a bounded cleanup path |
| 3. Loopback network | Test-target TCP/HTTP/UDP fixtures, traffic generator, parser and network sidecars using loopback-only configuration | Ports and fixtures are owned by the run; start/stop, worker enter/exit, cancellation state, timeout, elapsed time, and tracker return evidence are present; all listeners and fixture processes terminate |
| 4. MCP integration | Standalone MCP registration, schemas, handlers, routing, coverage ledger, cleanup contracts, and live localhost request path | Registration/schema checks pass; every planned case has a terminal ledger record or explicit dependency/cascade status; timed-out workers drain; live request path proves route entry and exit; no misleading empty result is accepted |
| 5. Camoufox | Camoufox install probe, bridge lifecycle, browser/page operations, browser-backed MCP cases | Probe completes within 9,000 ms and reports usable CPython 3.12, module, browser, and Python paths; launch has a 75,000 ms bound and watchdog slack; browser/bridge state proves stopped, no pending cleanup, and no orphan child |
| 6. Driver-backed | WhosWho memory, DTB, debugger, HWBP, remote-call, sandbox, network capture, and other privileged features | Operator-authorized host/VM; WhosWho is intentionally loaded; target attach, PID/DTB, IOCTL/status, VA/RVA/size/protection/state, and before/after cleanup evidence are complete; kernel and user logs agree; reboot follows any driver rebuild |

## Tier 1: Pure/Headless

**Prerequisites.** Configure the supported `ninja-msvc-release` preset. The C03 safe-headless manifest and its generated/staged runtime must be accepted. Safe-headless entries must remain driverless, network-free, application-free, target-free, debugger-free, and source/repository non-mutating.

**Evidence and bounds.** Ordinary entries allow one active process and a 120,000 ms wall limit. The approved decompiler quality scorer alone allows four active processes and a 1,800,000 ms wall limit. The runner verifies executable identity, SHA-256, build identity, result schema, assertion counts, finalized ledger, zero late writes, zero error flags, bounded stdout/stderr/result capture, and cancellation/deadline state.

**Commands.** No CTest command is documented here: repository CMake contains standalone executable targets but no `add_test()` registration. Use only the configured build's staged safe-headless entry point when its manifest supplies it; do not infer a path or command not present in the manifest.

**Promotion.** Promote only on a passed aggregate with integrity-clean ledger and no outstanding timed-out worker. A missing manifest, invalid identity, malformed result, timeout, or cancellation remains a non-promotion result.

## Tier 2: Local Process Fixture

**Prerequisites.** `AiDA_TestTarget.exe` is built and staged beside `AiDAStandalone.exe`; `target_protocol.exe` is staged under `test_binaries/target_protocol` and `deps/test_binaries/target_protocol` when that fixture is needed. The target is the CMake `AiDA_TestTarget` executable and is C++17/MSVC-built on Windows.

**Operational controls.** The target accepts `--duration <sec>`, `--skip-network`, `--no-external`, `--disable-re-fixtures`, `--disable-re-domain-fixtures`, `--disable-proto-re-fixtures`, and `--disable-protected-re-fixtures`. Use `--no-external` for a local-only run and disable fixtures not required by the selected test. Target startup proves PID, module base, `READY`, and `Local\\WhosWhoTestReady`; shutdown may be requested through `Local\\WhosWhoTestDone` or `Global\\WhosWhoTestDone`.

**Timeout/cancellation/cleanup evidence.** Capture target log work boundaries, PID/TID, launch path and working directory, exit code, and elapsed time. The done-event path waits up to 1,500 ms for the orchestrator and 1,000 ms for the listener, then closes handles and shuts down fixtures. Normal shutdown waits up to 10,000 ms for the orchestrator and 5,000 ms for the listener, then joins and closes handles. A wait that does not complete is cleanup failure, not pass.

**Commands.** Source-proven target CLI forms are `AiDA_TestTarget.exe --help`, `AiDA_TestTarget.exe --duration <sec> --no-external`, and `AiDA_TestTarget.exe --duration <sec> --skip-network`. Resolve the executable from the CMake-staged output; do not use a guessed current directory.

**Promotion.** Promote local-process features only after `READY`, valid target evidence, and clean process/fixture shutdown. Attach-dependent tests remain blocked when target launch, PID, DTB, allocation, or attach evidence is unavailable.

## Tier 3: Loopback Network

**Prerequisites.** Tier 2 target is running. Reserve the configured target TCP port and HTTP port; defaults in source are TCP `9876` and HTTP `18080`. Use `--no-external` to constrain opportunistic probes to loopback. Use the network sidecar only when its source-backed synchronization contract is selected.

**Side effects.** Opens local listeners, starts traffic generation, creates protocol fixtures, and may create capture/tracker state. No external network is permitted for this tier.

**Timeout/cancellation/cleanup evidence.** Record before/after listener and tracker start/stop, worker entry/exit, cancellation state, timeout, elapsed time, and whether `driver_bridge::get_captured_packets` returned. Prove port ownership is released, traffic and HTTP services stopped, sidecars exited, and target cleanup completed. Bounded tracker shutdown is mandatory; a hanging stop is a timeout even if packets were captured.

**Commands.** Source-proven target controls are `AiDA_TestTarget.exe --duration <sec> --no-external` and `AiDA_TestTarget.exe --duration <sec> --skip-network`. Do not publish commands for sidecars or services without a source-backed invocation in the selected test.

**Promotion.** Promote only with loopback-only evidence, complete tracker shutdown, and no orphan listener or sidecar. External DNS/HTTP success is not a requirement for this tier.

## Tier 4: MCP Integration

**Prerequisites.** Standalone MCP server and registered tool set are available. Use the in-application MCP Test Lab harness for coverage; it tracks planned cases, registered tools, aliases, dependency blocks, cascade blocks, functional evidence, and cleanup contracts.

**Evidence and bounds.** The harness records terminal status per case and requires coverage audit start/completion, no missing/stale audited tools, no unexpected zero-pass tools, no diagnostic fallback masquerading as functional success, and zero outstanding timed-out workers. For live MCP diagnosis, inspect `/health`, `/mcp`, and `tools/list`; correlate `mcp_srv` `request_entry`, route handler evidence, and `request_exit`. A bound port alone is not a pass.

**Side effects.** Mutating tools can change local sessions, workspaces, target state, files, memory, or network state. Run only the selected cases and preserve their cleanup contract. Do not expose credentials or captured sensitive bodies in evidence.

**Promotion.** Promote only after schema/contract checks, functional evidence where claimed, complete terminal ledger, drained timeouts, and cleanup postconditions. Dependency-blocked Camoufox or driver cases do not become MCP regressions.

## Tier 5: Camoufox

**Prerequisites.** Camoufox is the only supported browser. The source-staging path requires `camoufox-reverse-mcp/pyproject.toml`; app-local browser discovery checks `.deps/camoufox-135.0.1-beta.24-win.x86_64` and `camoufox-135.0.1-beta.24-win.x86_64` for `camoufox.exe`. Offline staging also requires bundled CPython 3.12.

**Probe and lifecycle.** The Test Lab dependency probe is bounded at 9,000 ms and disables setup/download. A usable result requires install state `ok`, nonempty Python path, module version, and browser path. Browser launch is bounded at 75,000 ms with 25,000 ms watchdog slack. Record bridge state, child PID/aliveness, browser/page verification, cleanup-pending state, and first failure. Stop bridge and browser before promotion.

**Side effects.** Starts Camoufox and its reverse-MCP bridge, creates browser contexts/pages, and may access user-selected web endpoints. No stock-browser fallback is allowed. Keep provider credentials and raw authentication material out of logs.

**Promotion.** Promote only when dependency probe, bridge readiness, requested browser operation, request/response evidence, and final stopped/no-pending-cleanup state all pass. Probe timeout or missing dependency is `dependency_blocked`.

## Tier 6: Driver-Backed

**Prerequisites.** Explicit operator authorization; research host or VM; controlled target; matching WhosWho user/kernel ABI; intentional driver load and attach. Do not run this tier casually or as a default prerequisite for lower tiers.

**Evidence.** Record user-mode driver status, kernel NTSTATUS/Win32 errors, IOCTL inputs/results, target PID/DTB, module base/end, VA/RVA/size/protection/state, memory before/after state, guard-page and protection transitions, debugger/HWBP state, and worker timing. Correlate `aida_full_test.log`, `aida_debug.log`, and `C:\Users\Public\Desktop\aida_kernel.log`.

**Side effects and cleanup.** Memory writes, remote calls, thread suspension/resume, debugger state, page guards, sandboxing, network capture, and injected traffic can alter the target or host. Use only the selected feature's documented destructive guard and cleanup path. Prove detach, worker idle, guard/protection restoration, capture/tracker stop, target termination, and handle release. Never claim cleanup from a successful IOCTL alone.

**Promotion.** Promote only when attach and operation evidence are complete and cleanup is proven in both user and kernel logs. If the driver was rebuilt or changed, reboot Windows before testing the new driver; WhosWho has no runtime unload routine.

## Message-Pump Gate

Every promotion involving `AiDAStandalone.exe`, Test Lab UI, MCP live requests, Camoufox, dialogs, or startup must include a responsiveness check after the IDE loads. Verify render/heartbeat progress and a responsive window. A stalled `SendMessageTimeout(WM_NULL)`, `IsHungAppWindow=True`, or advancing render logs with an unresponsive window is a message-pump failure until proven otherwise. Do not attribute it to Camoufox without evidence.

## Source Evidence

- `CMakeLists.txt`: standalone targets `AiDAParserProof` and `AiDA_NetworkHookSidecar`; Test Lab source registration; target and protocol-fixture staging; Camoufox discovery/staging; no `add_test()` registration.
- `src/standalone/test_target/CMakeLists.txt`: `AiDA_TestTarget`, `AiDA_TargetProtocolFixture`, output locations, Windows dependencies, and staging contract.
- `src/standalone/test_target/main.cpp`: CLI options, target READY/events, orchestrator/listener lifecycle, durations, and bounded shutdown waits.
- `src/standalone/src/core/testlab/test_lab.hpp`: outcome taxonomy, driverless/WhosWho lanes, and destructive feature guards.
- `src/standalone/src/core/testlab/test_lab_bounded_runner.hpp`: active-run cap, timeout, cancellation flag, executor cancellation, and exception result handling.
- `src/standalone/src/core/testlab/test_lab_features_c03_safe_headless.cpp`: safe-headless effect policy, resource bounds, manifest/result integrity, cancellation, and cleanup evidence.
- `src/standalone/src/core/testlab/test_all_mcp.cpp`: MCP case ledger, coverage audit, Camoufox probe/launch bounds, dependency blocking, and timeout-drain accounting.
- `src/standalone/src/main.cpp`: message-pump flags, send-only drain, and nonblocking empty-queue probe.
- `README.md`: Test Lab prerequisite semantics, cooperative cancellation, diagnostic evidence, driver reboot warning, Camoufox-only policy, and reliability model.
