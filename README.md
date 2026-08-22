# AiDA

AiDA is a Windows reverse-engineering workspace that brings static analysis,
live process inspection, debugging, network analysis, and AI-assisted research
into one environment.

The project has two primary user interfaces:

- **AiDA Standalone**, a native desktop IDE for investigating binaries,
  processes, memory, execution state, and network behavior.
- **AiDA for IDA Pro**, a plugin that extends an existing IDA database with
  AI-assisted analysis, automation, vulnerability research, and MCP tools.

Selected live-analysis features are backed by **WhosWho**, AiDA's Windows
kernel driver. Browser-assisted research uses **Camoufox**, the only browser
runtime supported by AiDA.

AiDA is designed as a personal research tool. It starts directly in the IDE:
there is no account, product activation, license prompt, telemetry service, or
AiDA-operated backend. User-configured AI providers, Camoufox setup or
browsing, MCP marketplace or package operations, symbol retrieval, and
explicitly selected network or interception workflows are the normal reasons
the application may contact external services.

> AiDA includes privileged process, memory, debugger, network, interception,
> and sandboxing capabilities. Use it only on systems, software, and traffic
> that you own or are authorized to analyze.

## Why AiDA Exists

Reverse engineering rarely happens in one tool or one mode. A typical
investigation moves repeatedly between questions such as:

- What does this binary contain?
- Where are its functions, strings, imports, exports, and references?
- What code reaches this call or data structure?
- What changes when the program runs?
- Which process, module, thread, or memory region owns an address?
- What does the program send over the network?
- Can a suspected vulnerability be reproduced or disproved?
- How can evidence from many views be kept in one coherent session?

AiDA is built around that full investigation loop. Static and live evidence
are treated as parts of the same workspace rather than separate products. The
goal is not to replace every specialist tool. The goal is to reduce context
switching, preserve evidence, and make complex investigations easier to
repeat, explain, and extend.

## The Short Version

Use AiDA when you want one place to move from a file to an explanation, from
an explanation to a running process, and from a running process to evidence.

| Surface | Best for | WhosWho driver |
| --- | --- | --- |
| AiDA Standalone | Full desktop workspace for binaries, processes, debugging, network analysis, and AI tools | Needed only for selected live and privileged features |
| AiDA for IDA Pro | Adding AiDA automation, AI context, vulnerability research, and MCP tools to an IDA database | Needed only for selected live and privileged features |

A typical investigation looks like this:

1. Open a binary and let AiDA build its workspace.
2. Inspect functions, strings, imports, references, types, and disassembly.
3. Ask the AI to summarize selected evidence or propose the next useful check.
4. Attach to an authorized test process when runtime behavior matters.
5. Compare memory, threads, breakpoints, network traffic, and static analysis.
6. Save the workspace, findings, and reasoning for later review.

Static analysis works without the kernel driver. Process manipulation,
driver-backed debugging, some network capture features, and selected sandbox
operations require additional privileges and a compatible WhosWho setup.

## Why a Security Researcher Would Use It

AiDA is aimed at investigations that keep crossing boundaries. The interesting
part is not any one disassembler view, scanner, debugger panel, or AI chat. The
interesting part is being able to move between them without throwing away the
identity and context of the investigation.

### Static facts can lead directly to runtime evidence

Start with a function, string, import, structure, or call path in a binary.
Then use the same investigation to examine the corresponding loaded module,
live bytes, memory region, thread, register state, breakpoint event, or network
activity in an authorized process.

Useful comparisons include:

- On-disk instructions versus the bytes currently mapped in memory
- Recovered control flow versus an observed execution path
- Static call sites versus arguments captured at a controlled API boundary
- A suspected structure layout versus bytes read from a live target
- A network parser in the binary versus the messages it actually processes
- An AI explanation versus the disassembly, memory, and debugger evidence that
  supports or contradicts it

This is the central reason to download AiDA: it reduces the gap between “I
found something interesting in the file” and “I have evidence for what it does
when it runs.”

### AI can operate on evidence, not only pasted code

AiDA's AI integration can use structured workspace, debugger, scanner, network,
emulation, and IDA MCP tools. A researcher can ask for a bounded investigation
step, inspect the returned evidence, and continue from the result.

The intended loop is:

1. Select a function, target, request, memory region, or finding.
2. Ask for an explanation, comparison, or next analysis step.
3. Let the AI request explicit read or mutation tools.
4. Review the tool result and the supporting evidence.
5. Keep, reject, or refine the conclusion.

AI output remains a hypothesis. AiDA's value is that the hypothesis can be
checked against structured tool results instead of relying on a confident
paragraph generated from incomplete pasted context.

### The IDA plugin is more than a chat panel

For IDA users, AiDA can expose functions, pseudocode context, references,
types, comments, imports, segments, search results, analysis metadata, and
vulnerability workflows through structured tools. It can also route requests
to multiple running IDA databases by instance identity or process ID.

That makes it possible to ask questions across several open samples or
versions while keeping each request tied to the correct IDA instance. Read
operations and database mutations are separate tool categories, so an AI
workflow can gather context without implicitly renaming, retyping, annotating,
or patching the database.

### Findings can remain connected to their evidence

AiDA persists sessions, workspace facts, chat context, findings, network
projects, scanner results, and analysis artifacts. Tool and AI activity can be
reviewed alongside the target and analysis state that produced it.

This helps with work that lasts longer than one sitting:

- Keep a hypothesis and its supporting call path together
- Return to a memory snapshot after restarting the application
- Compare changes between target generations
- Preserve rejected or unresolved hypotheses instead of losing them in chat
- Revalidate proposed changes after the target or database changes

Persistence is not an immutable forensic chain of custody. Stored sessions can
contain sensitive binaries, memory-derived data, traffic, and credentials from
the target environment.

### Privileged functionality is an extension, not a startup gate

The WhosWho driver adds selected live process, memory, debugger, network,
kernel-symbol, and analysis-target capabilities. It is useful when an
investigation requires more than static files, but AiDA Standalone does not
become unusable when the driver is unavailable.

The IDE can still be used for static work, sessions, AI-assisted reasoning,
disassembly, workspace analysis, and many non-privileged tools. Driver-backed
operations report their unavailable prerequisite instead of returning a fake
empty result.

### Network evidence is treated as research data

AiDA combines code-side investigation with connection, packet, protocol, HTTP,
browser, replay, comparison, crawler, and scanner workflows. That is useful
when a protocol or web finding cannot be understood from requests alone:

- Find the parser or serializer in the binary
- Trace the code that handles a field
- Observe the corresponding request or response
- Compare normal and modified behavior
- Record timing, status, length, hashes, reflection, JSON shape, or other
  differential evidence
- Link the result back to the code and target context

These tools support authorized testing. They do not turn an automated result
into a confirmed vulnerability without researcher review.

### Test Lab makes the integration testable

Many tools look impressive until a target disappears, a driver is missing, a
worker is cancelled, or a browser sidecar fails. AiDA includes an in-app Test
Lab and controlled `AiDA_TestTarget` fixture for exercising analysis,
debugger, memory, network, MCP, sandbox, and driver-related workflows.

Test Lab distinguishes successful behavior from unavailable prerequisites,
timeouts, crashes, malformed results, cancellation, and cleanup failures. It
is useful both for contributors and for researchers who want to verify the
local environment before trusting a larger investigation.

## Research Workflows

### Unfamiliar binary to runtime explanation

1. Open the binary in AiDA Standalone.
2. Review format metadata, imports, exports, strings, recovered functions,
   references, and control flow.
3. Select a suspicious function or data path and ask the AI for a structured
   explanation.
4. Open the relevant disassembly, types, and cross-references.
5. Attach to an authorized test process when static evidence is insufficient.
6. Compare loaded modules, live bytes, memory regions, threads, registers, and
   debug events with the workspace facts.
7. Save the conclusion, unresolved assumptions, and supporting snapshots.

### Candidate vulnerability to reviewable evidence

1. Identify a dangerous call, input source, dispatcher, parser, or check.
2. Trace references, call relationships, data flow, and reachable validation.
3. Use bounded taint, microcode, emulation, or solver-assisted analysis where
   the model fits the question.
4. Validate important assumptions against a controlled fixture or live target.
5. Record the candidate chain, evidence, rejected paths, and remaining gaps.
6. Treat the result as confirmed only when direct evidence supports the claim.

### API boundary to application behavior

1. Locate the relevant file, socket, HTTP, security, or IOCTL boundary in the
   binary.
2. Resolve the function in an authorized target and inspect selected call
   context or bounded argument data.
3. Observe related connections, requests, responses, or browser actions.
4. Compare normal and modified inputs using the network workspace.
5. Preserve the response evidence, timing, hashes, and code references.

### Multiple IDA databases with one AI workflow

1. Open the samples or versions in separate IDA instances.
2. Connect AiDA's IDA MCP integration to the running instances.
3. Route reads to one instance or compare read-only facts across instances.
4. Keep names, comments, types, and patches scoped to the intended database.
5. Review every mutating operation before applying it.

### Static library recognition to type recovery

AiDA's standalone analysis includes FLIRT-oriented recognition infrastructure,
RTTI and virtual-table inspection, and type-seed export paths. In practice,
recognized library functions can improve the context available for prototype,
class, and inheritance analysis instead of ending as isolated labels.

## Capability Matrix

| Research question | AiDA surface | Evidence produced | Main dependency |
| --- | --- | --- | --- |
| What is inside this file? | Standalone workspace or IDA plugin | Sections, imports, exports, strings, functions, references, types | Input format and successful analysis |
| What does this function do? | Disassembly, pseudocode, AI context | Instructions, control flow, callers, callees, types, explanation | Analysis quality and available decompiler context |
| Does it behave differently at runtime? | Live target, debugger, snapshots | Live bytes, modules, threads, registers, memory, events | Authorized target, permissions, often WhosWho |
| Where does an input reach? | Vulnerability and data-flow tools | Candidate source-to-sink paths and check coverage | Supported representation and manual validation |
| What does the program send? | Network workspace and Camoufox | Connections, flows, requests, responses, timing, browser context | Local network setup and authorized traffic |
| Can a code path be explored safely? | Emulation and verification | Bounded execution state and solver/model results | Appropriate bounded model; not full-system emulation |
| Can the result be reproduced? | Test Lab and controlled target | Pass, failure, timeout, crash, cancellation, prerequisite, cleanup status | Local fixtures, services, driver, browser, permissions |
| Can an AI help without losing control? | MCP and session tools | Structured reads, explicit mutations, logs, saved context | Trusted local client and configured provider |

## Reasons to Try AiDA

AiDA is worth evaluating if your work repeatedly moves between a disassembler,
debugger, memory scanner, network tool, notes, and an AI client. It is
especially relevant when you want:

- Static and live evidence in one investigation
- AI requests grounded in structured tool results
- A standalone workspace plus an IDA-native integration
- Optional privileged capabilities without making the entire IDE driver-bound
- Explicit distinction between inspection and mutation
- Persistent context, findings, and evidence across sessions
- A local-first tool without an AiDA account or telemetry service
- A Test Lab that reports environmental failures instead of hiding them

AiDA is less suitable if you need a polished commercial support contract,
identical analysis depth across every format and architecture, guaranteed
sandbox isolation, or demonstrated parity with established specialist
debuggers, decompilers, and web-security suites.

## What AiDA Does

### Binary Workspaces

AiDA Standalone can open binaries and related containers into persistent
analysis workspaces. The analysis stack includes infrastructure for PE, ELF,
Mach-O, COFF, APK, DEX, JAR, IPA, and ZIP-derived inputs, with architecture
support spanning x86, ARM, AArch64, MIPS, PowerPC, and RISC-V components.

Depending on the input and available analysis backend, a workspace can expose:

- Sections, segments, address spaces, and mapped ranges
- Imports, exports, symbols, relocations, and entry points
- Recovered functions and basic blocks
- Cross-references and call relationships
- Strings and searchable facts
- Types, structures, fields, and type candidates
- Disassembly and pseudocode-oriented views
- Analysis findings, annotations, and saved artifacts
- Graph and relationship views

Analysis results are published as versioned snapshots. Long-running work is
scheduled in the background so the UI can remain responsive, and stale work
is rejected when a workspace or target changes.

Support is not necessarily identical across every file format or processor.
AiDA reports unsupported or incomplete operations instead of implying that
all formats have equal analysis depth.

### Disassembly and Decompilation

The standalone IDE includes native disassembly views and decompilation-oriented
workflows. It uses Zydis and Ghidra-derived components alongside AiDA's own
workspace, indexing, type, and presentation layers.

These views are intended for practical code navigation:

- Follow control flow and references
- Move between assembly and higher-level representations
- Inspect function boundaries and calling behavior
- Apply or infer names and types
- Compare static interpretation with live process evidence
- Feed selected context into AI-assisted analysis

The standalone decompiler is its own implementation and integration. It is
not presented as a drop-in replacement for IDA or Hex-Rays.

### Live Process Analysis

When a process is attached, AiDA can correlate the current target with its
modules, threads, address space, and analysis views. Available operations vary
with permissions and driver availability, but the runtime model includes:

- Process and module enumeration
- Virtual memory reads and writes
- Memory-region queries and protection information
- Allocation and cleanup in a selected target
- Thread enumeration and state inspection
- Register and thread-context access
- Export and module resolution
- Virtual-to-physical address translation
- Debug-event collection
- Controlled remote-call support

Target identity matters throughout AiDA. Asynchronous reads and UI refreshes
are tied to a process and target generation so results from an old process are
not silently published into a new session.

### Debugging

AiDA contains a custom debugger workspace for inspecting and controlling live
targets. Its source-backed capabilities include:

- Register and thread views
- Stack, memory dump, and disassembly refreshes
- Software and hardware breakpoints
- Stepping and run-to-address workflows
- Thread suspension and resumption
- Source and symbol integration
- Memory maps, modules, handles, SEH information, and thread intelligence
- Debug-event timelines

The debugger favors explicit target validation and cleanup. Breakpoints,
temporary suspensions, and target-owned launch resources are tracked so failed
or cancelled operations do not silently leak state into later debugging work.

AiDA is not intended to claim feature parity with WinDbg, Visual Studio, or
IDA's debugger. It provides a focused debugger designed to work with the rest
of the AiDA workspace.

### Memory Scanning and Runtime Discovery

The standalone scanner suite is designed for both interactive inspection and
repeatable searches. It includes infrastructure for:

- Value and region scanning
- AOB and signature generation
- Pointer scanning
- Snapshot comparison
- Structure-oriented inspection
- String and cryptographic-material searches
- Saved scan catalogs and reusable results

Scanner jobs retain their target identity and cancellation state. This is
important when several analyses run at once or the user switches processes
while a scan is still active.

### Emulation and Verification

AiDA integrates instruction emulation and symbolic or solver-assisted analysis
through components including Unicorn, Triton, and Z3.

These facilities support workflows such as:

- Exploring a bounded code path without running the full program
- Testing assumptions about register or memory state
- Checking whether a branch or condition is feasible
- Supporting vulnerability analysis with stronger evidence
- Comparing static conclusions with an executable model

Emulation is intentionally bounded. It does not imply complete operating
system, device, syscall, or hardware emulation.

### Vulnerability Research

AiDA includes tools for finding, organizing, and validating potential security
issues in software under analysis. Both the standalone application and IDA
plugin contain vulnerability-oriented workflows.

Source areas cover topics such as:

- Dangerous API and call-site discovery
- Taint and data-flow analysis
- Check-bypass and reachability analysis
- Binary and kernel attack-surface review
- IOCTL and dispatcher analysis
- Symbolic and SMT-assisted verification
- Structured findings and supporting evidence

These tools produce hypotheses and evidence, not guarantees. A reported path
must still be reviewed in context, and the absence of a finding does not prove
that a program is secure.

### Network and HTTP Analysis

AiDA Standalone includes an integrated network workspace for observing and
investigating application traffic. It combines protocol, interception,
replay, scanning, and browser-assisted workflows.

The network subsystem includes source-backed components for:

- Connection and packet inspection
- Protocol parsing and flow storage
- HTTP interception and replay
- TLS certificate and interception workflows
- Request and response comparison or decoding
- Crawling and content discovery
- Active and passive scanning
- Intruder-style request mutation
- Parameter, authentication, JWT, API, JavaScript, and GraphQL analysis
- Sequencing, logging, issue tracking, and reporting
- Collaborator-style interaction workflows

Several views follow a Burp-style organization because that vocabulary is
familiar to web-security researchers. AiDA is not marketed as a complete Burp
Suite replacement, and individual modules may depend on local configuration,
the target environment, Camoufox, or the kernel driver.

Captured traffic can contain credentials, session identifiers, personal data,
and application secrets. Treat projects, logs, exports, and screenshots as
sensitive research material.

### Camoufox Browser Research

Camoufox is AiDA's supported browser for web research and browser-driven
analysis. It is used for workflows such as:

- Navigating pages from an AiDA session
- Collecting browser-visible network and page context
- Browser-backed search and retrieval
- Correlating requests with pages and navigation actions
- Exercising web-analysis tools against an authorized target

AiDA intentionally does not fall back to Chrome, Edge, stock Firefox, the
system default browser, or a Playwright-managed generic browser. This keeps
browser behavior and privacy assumptions consistent.

The build can stage the browser, reverse-MCP source, Python runtime, and sidecar
dependencies beside the application when the corresponding local dependencies
are available. AiDA validates the expected runtime contract before marking
browser integration ready. Browser support is unavailable when that local
runtime is incomplete or incompatible; unrelated IDE features can still
operate.

### Analysis-Target Sandboxing

AiDA can launch selected programs with containment and observation options.
Depending on the selected mode and the host configuration, launch support can
use Windows jobs, AppContainer, Windows Sandbox, firewall rules, and
driver-backed analysis-target controls.

This functionality is for containing and studying an analysis target. It is
not AiDA self-protection, endpoint security, or an absolute isolation
guarantee. Sandboxing strength depends on Windows, permissions, enabled
features, and the behavior being tested.

Launch resources are tracked as a unit. Process handles, jobs, temporary
firewall rules, AppContainer profiles, sandbox directories, and guest bridges
are cleaned up after the target exits or when a launch fails.

## The IDA Pro Plugin

The IDA plugin is for researchers who want AiDA's automation and AI workflows
inside an existing IDA database.

It adds:

- IDA-aware function, memory, segment, import, type, and comment tools
- Navigation, naming, annotation, and patching operations
- Hex-Rays-aware context where the installed IDA environment provides it
- GraphRAG and persisted analysis context
- Emulation and vulnerability-analysis tools
- Batch analysis and metadata operations
- MCP access to the current IDA instance
- Routing across multiple open IDA instances

The plugin uses IDA's own database and APIs. AiDA Standalone uses a separate
workspace model. They are complementary interfaces, not two skins over an
identical backend.

## AI-Assisted Analysis

AiDA can connect to user-selected AI providers. The AI layer is intended to
help with tasks such as:

- Explaining a function or code region
- Summarizing evidence from several views
- Planning a reverse-engineering investigation
- Generating and refining hypotheses
- Requesting bounded tool calls
- Comparing static and runtime evidence
- Recording useful conclusions in the active session

AI output is not treated as ground truth. The useful part of the integration
is its access to structured, tool-generated context. Claims should be checked
against disassembly, memory, debugger state, logs, or other direct evidence.

Provider credentials belong to the user. AiDA stores user authentication and
API material locally using Windows-protected storage mechanisms where
available. Credentials, OAuth tokens, private keys, and plaintext secrets must
not be copied into bug reports or diagnostic logs.

AiDA itself has no account service, license server, telemetry endpoint, or
update server.

## MCP and Tool Automation

AiDA exposes Model Context Protocol tools so compatible AI clients can work
with structured analysis operations instead of relying only on copied text.

Tool domains include:

- Workspace and session operations
- Disassembly and decompilation
- Process, memory, module, and thread inspection
- Debugger control
- Scanning and reverse-engineering helpers
- Network and browser analysis
- Emulation and verification
- Coding and workflow tools
- IDA-compatible read and mutation operations

The standalone MCP server binds to loopback. Loopback does not make it
harmless: some tools can alter files, sessions, debugger state, target memory,
network projects, or an IDA database. Treat the MCP server as a local trust
boundary. Only connect clients you trust, review requested operations, and do
not expose the service to untrusted networks.

AiDA applies request limits, worker quotas, cancellation, and shutdown
tracking so long-lived MCP operations do not monopolize the IDE's shared work
queues.

## WhosWho Kernel Driver

WhosWho is AiDA's privileged Windows driver for selected live-analysis,
debugger, memory, network, and analysis-target sandbox features.

The driver and user-mode bridge implement operations including:

- Process address-space and DTB resolution
- Physical and virtual memory access
- Module, export, memory-region, and PEB inspection
- Thread enumeration, context access, and hardware breakpoints
- Debug-event publication
- Remote memory and controlled call support
- Connection and packet inspection
- DNS, WFP, stream, injection, redirection, and PCAP-related operations
- Analysis-target sandbox controls

Driver-backed features require administrative privileges and a compatible
Windows environment. Driver failure is non-fatal to AiDA Standalone: the IDE
can still start, and features that require WhosWho report that they are
unavailable rather than fabricating empty success.

The driver is built separately, embedded as a plain generated byte array, and
materialized locally when AiDA needs to load it. WindMapper is attempted first,
with a native Windows driver-service path available as a fallback.

WhosWho has no runtime unload routine. After rebuilding or changing the
driver, reboot Windows before testing the new driver. Loading kernel code can
crash or destabilize the machine; use a suitable research host or virtual
machine and preserve important work first.

## Test Lab

Test Lab is AiDA's in-application validation surface. It combines controlled
fixtures, feature registration, evidence collection, and cleanup into one
place.

The repository includes an `AiDA_TestTarget` process that exposes predictable
memory, thread, control-flow, protocol, and network fixtures. Test Lab can use
that target to validate features without depending on an arbitrary external
application.

Test Lab emphasizes prerequisite-aware reporting. If a target cannot launch,
the driver cannot attach, or a required service is unavailable, dependent
tests are reported as prerequisite failures rather than as misleading feature
regressions.

Cancellation is cooperative. A cancellation request prevents subsequent tests
from starting, but a synchronous low-level operation already in progress is
allowed to return before its ownership and cleanup state are released.

Some tests have meaningful side effects. Read the selected test description
and use the controlled test target unless a different target is intentional.

## Sessions and Persistence

AiDA persists investigation state so analysis can continue across restarts.
The standalone application uses SQLite and JSON-backed storage for areas such
as:

- Chat and conversation history
- Analysis sessions and workspace metadata
- Cost and provider usage records
- Network projects, findings, and payload sets
- Saved scanner and analysis artifacts
- User settings and UI state

Most user data is stored below the Windows AppData locations. Exact paths can
vary by subsystem and Windows profile configuration.

Closing a workspace, process, or application is treated as a lifecycle event,
not just a UI action. Background work is cancelled or drained, late results
are rejected, and owned resources are released before their dependent state is
destroyed.

## Diagnostics and Evidence

AiDA keeps detailed diagnostics because low-level failures cannot be diagnosed
reliably from source structure alone.

Important evidence sources include:

| Evidence | Purpose |
| --- | --- |
| `aida_debug.log` | Canonical standalone runtime, AI, MCP, browser, driver-bridge, and lifecycle log |
| `aida_early_startup.log` | Failures before normal application diagnostics are ready |
| `aida_crash.log` | Direct crash breadcrumbs and critical shutdown evidence |
| `WindMapper_debug.log` | Driver staging, mapper launch, exit, and cleanup evidence |
| `C:\Users\Public\Desktop\aida_kernel.log` | Kernel-side WhosWho operations and failures |
| `aida_full_test.log` | Test Lab run, prerequisites, phases, cancellation, and cleanup evidence |
| `C:\CrashDumps\AiDAStandalone.exe.<pid>.dmp` | Native exception state and stack analysis when WER dump collection is configured |

Application logs are normally placed beside `AiDAStandalone.exe`. Build logs
are written under the Windows temporary directory by the build wrapper.

Diagnostics intentionally capture process IDs, thread IDs, addresses, sizes,
status codes, timing, queue state, and lifecycle phases. They should not
capture raw provider credentials, OAuth tokens, private keys, DPAPI plaintext,
or other authentication material.

For a crash, hang, startup stall, driver failure, or Test Lab failure, inspect
the relevant logs and dump before assigning a root cause. The first confirmed
failure marker is more useful than a theory based only on nearby code.

## Privacy and Network Behavior

AiDA is local-first.

It does not include:

- Product activation
- A license or entitlement service
- Telemetry or analytics reporting
- An AiDA account system
- An update server
- A phone-home mechanism
- Self-protection, anti-tamper, packing, or string-obfuscation systems

AiDA may make outbound connections when the user explicitly enables or invokes
features that require them, including:

- User-configured AI provider endpoints
- Camoufox browsing and web research
- Package registries used by MCP marketplace workflows
- Symbol retrieval for debugging and kernel-symbol analysis
- Python or package downloads when the user enables the corresponding setup path
- Network tests or interception workflows selected by the user

Captured binaries, memory, traffic, chat history, provider settings, and
analysis databases can all be sensitive. The operator is responsible for
storage, backups, sharing, and deletion of that data.

## Reliability Model

AiDA performs many operations concurrently, but UI responsiveness and target
correctness take priority over maximizing background throughput.

Core reliability principles include:

- The Win32 message pump remains owned by the UI thread.
- Long-running operations use managed worker queues or owned native threads.
- Work is associated with a subsystem, target, generation, and cancellation
  state where applicable.
- Results are validated again before publication.
- Shutdown requests cancellation before destroying shared resources.
- Bounded waits report incomplete shutdown rather than pretending work ended.
- Driver and target errors remain distinguishable from valid empty results.
- Diagnostic breadcrumbs remain available for later evidence review.

The project still contains complex, privileged, and environment-dependent
code. A successful compile does not prove live debugger, driver, browser, or
network behavior. Runtime verification remains part of the development model.

## Main Components

| Component | Role |
| --- | --- |
| `AiDAStandalone.exe` | Native Win32, DirectX 11, and ImGui reverse-engineering IDE |
| `AiDA.dll` | IDA Pro plugin and IDA-native MCP integration |
| `WhosWho.sys` | Kernel driver for selected privileged analysis features |
| `AiDAWindMapper.exe` | Privileged WhosWho loading and mapping utility |
| `AiDAGuestAgent.exe` | Guest-side support for VM-assisted workflows |
| `AIDADialogBroker.exe` | Isolated dialog and process-broker support |
| `AiDA_TestTarget.exe` | Controlled target used by Test Lab |

The standalone source is organized by capability under
`src/standalone/src/core`. Shared plugin and analysis code lives under `src`,
driver communication under `driver`, the kernel implementation under
`driver/WhosWho`, and the mapper under `mapper`.

## Getting AiDA Running

AiDA is a Windows x64 CMake project built with Visual Studio 2022, MSVC, Ninja,
Python 3, OpenSSL development libraries, and pinned local dependencies. The
canonical standalone configuration is the `ninja-msvc-release` preset.

The repository build wrapper can handle Visual Studio environment discovery,
optional driver builds, CMake configuration when needed, the main build, an
optional verification build, and timestamped logs. The common entry points are:

```powershell
# Incremental standalone build
.\build-host.cmd

# Full clean build, including WhosWho and WindMapper
.\build-host.cmd -FullClean

# Inspect the full build plan without executing it
.\build-host.cmd -PlanOnly -FullClean
```

The normal standalone output is `build-ninja\AiDAStandalone.exe`.

The supported preset defaults to the standalone application and disables the
IDA plugin. Building `AiDA.dll` is a separate configuration that requires a
compatible IDA SDK. Driver rebuilds require a Windows reboot before the new
WhosWho image can be tested.

Dependencies are pinned under `.deps` and related source directories. AiDA is
not designed to silently substitute arbitrary system versions for its binary
analysis, browser, solver, or runtime dependencies.

## Project Status and Expectations

AiDA is an active personal research project with a broad source surface. Some
features are mature and used together regularly; others are specialized,
experimental, dependent on external software, or meaningful only on a
particular Windows configuration.

When evaluating a feature, distinguish between:

- Source support: the implementation and integration exist.
- Build support: the current dependency set compiles the implementation.
- Runtime availability: required driver, browser, SDK, symbols, target, or
  permissions are present.
- Runtime validation: the exact workflow has been exercised and produced
  current evidence.

This distinction is especially important for kernel operations, browser
automation, sandboxing, symbolic execution, interception, and target-specific
debugging.

## Responsible Use

AiDA is dual-use reverse-engineering software. It can inspect and modify live
processes, analyze protected or malicious programs, intercept traffic, mutate
requests, and expose powerful operations through local automation.

Use AiDA only when you have clear authorization. Follow applicable laws,
contracts, organizational policy, and disclosure requirements. Prefer
controlled fixtures, virtual machines, disposable analysis environments, and
the included test target when validating risky operations.

The software is provided for research and engineering use without a guarantee
that a sandbox, debugger operation, kernel request, AI conclusion, or security
finding is complete or safe for every environment.

## Contributing

Changes should be evidence-driven and narrowly scoped. For crashes and hangs,
start with logs or dumps. For driver changes, keep the user/kernel ABI in sync
and rebuild the full driver embed pipeline. For standalone changes, preserve
the Win32 message pump, UI-thread ownership, cancellation, and shutdown
ordering.

Before submitting a change:

- Explain the observed problem and evidence.
- Keep unrelated workspace changes out of the patch.
- Add or preserve diagnostics around low-level failure paths.
- Verify the smallest relevant source or test surface.
- Run the canonical build when the required environment is available.
- State clearly which runtime workflows were and were not exercised.

`AGENTS.md` contains the repository's detailed engineering and verification
contract.
