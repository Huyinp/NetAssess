# Windows Process Traffic Monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an elevated native C++ GUI that monitors per-process TCP/UDP traffic on Windows Server 2016+, infers common application protocols from ports, and displays totals and live rates.

**Architecture:** A private real-time ETW SystemTraceProvider session feeds decoded network events to a thread-safe aggregator. A native Win32 ListView reads immutable snapshots once per second, formats and sorts them, and keeps all ETW work off the UI thread.

**Tech Stack:** C++20, Win32, ETW/TDH, CMake, MSVC, CTest, Windows SDK; no third-party runtime or test framework.

**Spec:** `docs/superpowers/specs/2026-08-18-windows-process-traffic-monitor-design.md`

## Global Constraints

- Target Windows Server 2016 and later with Desktop Experience.
- Build x64 only and define `_WIN32_WINNT=0x0A00` and `UNICODE`.
- Produce a Windows-subsystem GUI executable with a `requireAdministrator` manifest.
- Use only Windows APIs and the C++ standard library; do not add a driver or third-party dependency.
- Application protocol detection is explicitly port-based inference, not payload inspection.
- Use a uniquely named private system logger; never stop or modify another ETW session.
- Follow test-first development: observe each behavioral test fail before adding its production implementation.

## Build Commands

Run these commands from the repository root in PowerShell:

```powershell
$netAssessCmake = 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $netAssessCmake -S . -B build -A x64
& $netAssessCmake --build build --config Debug
& $netAssessCmake --build build --config Release
& $netAssessCmake --build build --config Debug --target RUN_TESTS
```

---

### Task 1: Build Skeleton and Protocol Inference

**Files:**
- Create: `CMakeLists.txt`
- Create: `resources/app.manifest`
- Create: `src/traffic_types.h`
- Create: `src/protocol_classifier.h`
- Create: `src/protocol_classifier.cpp`
- Create: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `TransportProtocol`, `TrafficDirection`, `ApplicationProtocol` enums.
- Produces: `ApplicationProtocol InferApplicationProtocol(TransportProtocol, TrafficDirection, uint16_t source_port, uint16_t destination_port)`.
- Produces: `std::wstring_view ApplicationProtocolName(ApplicationProtocol)`.

- [ ] **Step 1: Add the CMake targets and write failing protocol tests**

Create a tiny test runner in `tests/unit_tests.cpp` with a `CHECK_EQ` macro that prints file, line, actual, and expected values and returns a nonzero process exit code when any assertion fails. Add tests that include the not-yet-existing `protocol_classifier.h` and assert:

```cpp
CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                  TrafficDirection::Send, 50000, 443),
         ApplicationProtocol::HttpsTls);
CHECK_EQ(InferApplicationProtocol(TransportProtocol::Udp,
                                  TrafficDirection::Send, 50000, 443),
         ApplicationProtocol::Quic);
CHECK_EQ(InferApplicationProtocol(TransportProtocol::Udp,
                                  TrafficDirection::Receive, 53, 50000),
         ApplicationProtocol::Dns);
CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                  TrafficDirection::Send, 50000, 49152),
         ApplicationProtocol::Other);
CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                  TrafficDirection::Send, 22, 443),
         ApplicationProtocol::HttpsTls);
CHECK_EQ(InferApplicationProtocol(TransportProtocol::Tcp,
                                  TrafficDirection::Receive, 22, 443),
         ApplicationProtocol::Ssh);
```

Define `NetAssessCore` as a static library containing the protocol classifier and `NetAssessTests` as a console test executable, then register `NetAssessTests` with CTest. The `WIN32` GUI target and its Windows libraries are added in Task 7 when `main.cpp` exists, so this task's RED failure is caused only by the missing classifier API.

- [ ] **Step 2: Configure and build to verify RED**

Run the Debug configure/build commands.

Expected: compilation fails because `protocol_classifier.h` does not exist.

- [ ] **Step 3: Implement the minimal protocol types and classifier**

Define enum values for `Ftp`, `Ssh`, `Smtp`, `Dns`, `Dhcp`, `Http`, `Pop3`, `Ntp`, `Imap`, `Ldap`, `HttpsTls`, `Quic`, `Smb`, `IpsecIke`, `SqlServer`, `MySql`, `Rdp`, `PostgreSql`, `Redis`, `MongoDb`, and `Other`.

Implement a `Lookup(TransportProtocol, uint16_t)` switch/table containing exactly the mappings in the spec. Select the primary port as destination for send and source for receive; if primary maps to `Other`, try the secondary port. `ApplicationProtocolName` returns the Chinese display name and appends `（端口推断）` for every value except `Other`, which returns `其他`.

- [ ] **Step 4: Build and run tests to verify GREEN**

Run the Debug build and `RUN_TESTS` target.

Expected: all protocol tests pass.

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt resources/app.manifest src/traffic_types.h src/protocol_classifier.h src/protocol_classifier.cpp tests/unit_tests.cpp
git commit -m "feat: add protocol inference core"
```

---

### Task 2: Traffic Aggregation, Rates, and Saturation

**Files:**
- Modify: `src/traffic_types.h`
- Create: `src/traffic_aggregator.h`
- Create: `src/traffic_aggregator.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: protocol enums from Task 1.
- Produces: `ProcessInstanceId`, `TrafficKey`, `TrafficEvent`, and `TrafficSnapshot` value types.
- Produces: `TrafficAggregator::Add`, `TrafficAggregator::Snapshot`, and `TrafficAggregator::Clear`.

- [ ] **Step 1: Write failing aggregation isolation tests**

Add tests that create four `TrafficEvent` values differing by PID, process creation time, transport, or application protocol. Assert that `Snapshot(t0)` returns four rows and that send bytes affect only `sent_bytes` while receive bytes affect only `received_bytes`.

Use these public shapes:

```cpp
struct ProcessInstanceId {
    std::uint32_t pid{};
    std::uint64_t creation_time_100ns{};
    auto operator<=>(const ProcessInstanceId&) const = default;
};

struct TrafficEvent {
    TrafficKey key;
    std::wstring process_name;
    TrafficDirection direction{};
    std::uint64_t bytes{};
};

class TrafficAggregator {
public:
    void Add(const TrafficEvent& event);
    std::vector<TrafficSnapshot> Snapshot(std::chrono::steady_clock::time_point now);
    void Clear();
};
```

- [ ] **Step 2: Build to verify RED**

Expected: compilation fails because `traffic_aggregator.h` is missing.

- [ ] **Step 3: Implement keyed cumulative aggregation**

Back the aggregator with `std::map<TrafficKey, Entry>` protected by `std::mutex`. Store process name and two `uint64_t` counters. Implement a `SaturatingAdd` helper using `UINT64_MAX - current < increment` before addition.

- [ ] **Step 4: Run tests to verify GREEN**

Expected: row isolation and direction tests pass.

- [ ] **Step 5: Write failing rate, clear, and overflow tests**

Use controlled time points `t0` and `t0 + 2s`. Verify the first snapshot has zero speeds, adding 2048 sent and 1024 received bytes before the second snapshot produces 1024 B/s and 512 B/s, `Clear()` removes all rows and resets the baseline, and adding past `UINT64_MAX` saturates rather than wraps.

- [ ] **Step 6: Run tests to verify RED**

Expected: rate and saturation assertions fail while isolation tests still pass.

- [ ] **Step 7: Implement rate baselines, clear, and saturation**

Each entry stores previous snapshot counters. The aggregator stores an optional previous snapshot time. If no baseline exists, elapsed time is nonpositive, or a counter moved backward, report zero speed. On a valid interval use `double(delta_bytes) / elapsed_seconds`. `Clear()` empties entries and resets the optional time.

- [ ] **Step 8: Run all tests to verify GREEN and commit**

```powershell
git add CMakeLists.txt src/traffic_types.h src/traffic_aggregator.h src/traffic_aggregator.cpp tests/unit_tests.cpp
git commit -m "feat: aggregate per-process traffic and rates"
```

---

### Task 3: Display Formatting and Stable Sorting

**Files:**
- Create: `src/formatting.h`
- Create: `src/formatting.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: `TrafficSnapshot` from Task 2.
- Produces: `FormatBytes`, `FormatRate`, `ProcessStatusText`, `SortColumn`, and `SortTrafficRows`.

- [ ] **Step 1: Write failing formatting and sorting tests**

Assert exact outputs:

```cpp
CHECK_EQ(FormatBytes(0), L"0 B");
CHECK_EQ(FormatBytes(1024), L"1 KB");
CHECK_EQ(FormatBytes(1536), L"1.5 KB");
CHECK_EQ(FormatBytes(1024ULL * 1024 * 1024), L"1 GB");
CHECK_EQ(FormatRate(2048.0), L"2 KB/s");
CHECK_EQ(ProcessStatusText(true), L"运行中");
CHECK_EQ(ProcessStatusText(false), L"已结束");
```

Create three rows with combined speeds 10, 30, and 20 B/s. Verify default descending speed order is 30, 20, 10. Verify PID ascending and process-name case-insensitive ascending sorts are deterministic, using `TrafficKey` as the final tie-breaker.

- [ ] **Step 2: Build to verify RED**

Expected: compilation fails because `formatting.h` is missing.

- [ ] **Step 3: Implement formatting and sort helpers**

Use a 1024 divisor, units `B`, `KB`, `MB`, `GB`, `TB`, and `std::wostringstream` with at most two fractional digits and no trailing zeros. Clamp nonfinite or negative rates to zero for display. Define sort columns for every UI column plus `CombinedSpeed`; ascending/descending is an argument.

- [ ] **Step 4: Run tests to verify GREEN and commit**

```powershell
git add CMakeLists.txt src/formatting.h src/formatting.cpp tests/unit_tests.cpp
git commit -m "feat: format and sort traffic rows"
```

---

### Task 4: Process Identity Cache and PID Reuse Protection

**Files:**
- Create: `src/process_info.h`
- Create: `src/process_info.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `ProcessInfo { ProcessInstanceId id; std::wstring name; bool alive; }`.
- Produces: `ProcessInfoCache::Resolve(uint32_t pid, uint64_t fallback_observation_id)` and `ProcessInfoCache::RefreshAlive(ProcessInstanceId)`.

- [ ] **Step 1: Write failing live and inaccessible process tests**

Resolve `GetCurrentProcessId()` and assert PID equality, nonempty executable base name, nonzero creation time, and `alive == true`. Resolve PID `0xFFFFFFFFu` with fallback ID `42` and assert name `受限进程 (4294967295)`, creation identifier `42`, and `alive == false`.

- [ ] **Step 2: Build to verify RED**

Expected: compilation fails because `process_info.h` is missing.

- [ ] **Step 3: Implement Windows process lookup and cache**

Open with `PROCESS_QUERY_LIMITED_INFORMATION`, call `GetProcessTimes` for creation time, call `QueryFullProcessImageNameW`, and retain only the final path component. Cache by PID, but before reuse return the cached instance only while the process handle creation time still matches. For inaccessible/finished processes use the specified fallback observation ID and placeholder name. `RefreshAlive` reopens the PID and compares creation time, so a reused PID does not mark an old row alive.

- [ ] **Step 4: Run tests to verify GREEN and commit**

```powershell
git add CMakeLists.txt src/process_info.h src/process_info.cpp tests/unit_tests.cpp
git commit -m "feat: resolve stable process identities"
```

---

### Task 5: ETW Payload Decoder with Cached Layouts

**Files:**
- Create: `src/etw_decoder.h`
- Create: `src/etw_decoder.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `DecodedNetworkEvent { pid, direction, transport, source_port, destination_port, bytes }`.
- Produces: a public test seam `DecodePayload(const EventLayout&, std::span<const std::byte>)`.
- Produces: `EtwDecoder::Decode(const EVENT_RECORD&)` and `EtwDecoder::parse_failures()`.

- [ ] **Step 1: Write failing bounded-payload decoder tests**

Construct a synthetic payload with 32-bit PID, 32-bit size, and two 16-bit network-order ports. Provide an `EventLayout` containing offsets and widths. Verify correct values and `ntohs` conversion. Then truncate the payload by one byte and assert decoding returns `std::nullopt` rather than reading out of bounds.

- [ ] **Step 2: Build to verify RED**

Expected: compilation fails because `etw_decoder.h` is missing.

- [ ] **Step 3: Implement safe layout-based decoding**

Define checked little-endian reads for PID/size and a checked network-order read for ports. Reject missing fields, unsupported widths, zero-byte payloads, and any offset-plus-width beyond `UserDataLength`.

- [ ] **Step 4: Run tests to verify GREEN**

Expected: synthetic and truncated-payload tests pass.

- [ ] **Step 5: Write failing schema cache tests**

Expose cache statistics only to tests through `EtwDecoder::cached_layout_count()`. Feed two records with the same schema key through a small internal schema-loader callback and assert the callback runs once; feed a different version and assert it runs again.

- [ ] **Step 6: Implement TDH layout discovery and cache**

Key the cache by provider GUID, event opcode/type, version, and 32/64-bit header flag. On a miss call `TdhGetEventInformation`, walk top-level properties in payload order, calculate each fixed field width from `EVENT_PROPERTY_INFO`, and capture offsets for case-insensitive names `PID`, `size`, `sport`, and `dport`. Derive TCP/UDP, IPv4/IPv6, and send/receive only from documented provider GUID and event type/opcode values. Cache both valid and invalid schemas so malformed high-frequency events are not repeatedly analyzed. Increment `parse_failures` for every event that cannot produce a complete `DecodedNetworkEvent`.

- [ ] **Step 7: Run tests to verify GREEN and commit**

```powershell
git add CMakeLists.txt src/etw_decoder.h src/etw_decoder.cpp tests/unit_tests.cpp
git commit -m "feat: decode ETW network events safely"
```

---

### Task 6: Private ETW Session Lifecycle

**Files:**
- Create: `src/etw_monitor.h`
- Create: `src/etw_monitor.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: decoder, process cache, classifier, and aggregator.
- Produces: `EtwMonitor::Start`, `EtwMonitor::Stop`, `EtwMonitor::running`, `EtwMonitor::events_lost`, `EtwMonitor::parse_failures`, and `EtwMonitor::last_error`.

- [ ] **Step 1: Write failing lifecycle state tests with an injected session API**

Define the smallest `IEtwSessionApi` seam around `StartTraceW`, `OpenTraceW`, `ProcessTrace`, `CloseTrace`, and `ControlTraceW`. A deterministic fake records calls. Assert:

- successful start sets running and starts exactly one consumer thread;
- calling `Start` twice does not create a second session;
- `Stop` calls control-stop and close only for the owned name/handles;
- calling `Stop` twice is harmless;
- a start failure leaves `running == false` and exposes the Windows error code.

- [ ] **Step 2: Build to verify RED**

Expected: compilation fails because `etw_monitor.h` is missing.

- [ ] **Step 3: Implement ownership-safe session lifecycle**

Generate `NetAssess-{current PID}-{GUID}` as the logger name. Configure real-time system logger mode, QPC clock, `WNODE_FLAG_TRACED_GUID`, and only `EVENT_TRACE_FLAG_NETWORK_TCPIP`. Start the session, open it in `PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD`, and run `ProcessTrace` on a `std::jthread`.

The static event callback retrieves `this` from `EVENT_TRACE_LOGFILEW.Context`, decodes the event, resolves process identity, infers application protocol, and submits `TrafficEvent`. `Stop` first atomically changes state, then calls `ControlTraceW(...STOP)`, `CloseTrace`, and joins. Never query for or stop a name not stored in the monitor instance.

- [ ] **Step 4: Run tests to verify GREEN and commit**

```powershell
git add CMakeLists.txt src/etw_monitor.h src/etw_monitor.cpp tests/unit_tests.cpp
git commit -m "feat: manage private ETW traffic session"
```

---

### Task 7: Native Win32 Traffic Window

**Files:**
- Create: `src/main_window.h`
- Create: `src/main_window.cpp`
- Create: `src/main.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: monitor status, aggregator snapshots, process liveness, formatting, and sorting.
- Produces: elevated GUI application with start/stop, clear, filter, sortable ListView, and status bar.

- [ ] **Step 1: Write failing view-state tests**

Keep HWND manipulation out of tests. Add a pure `BuildVisibleRows(snapshot, filter, sort_column, ascending, alive_lookup)` function declared in `main_window.h`. Assert that filtering is case-insensitive, filtered rows remain in the input snapshot, liveness sets `运行中/已结束`, and default order uses combined speed descending.

- [ ] **Step 2: Build to verify RED**

Expected: compilation fails because `main_window.h` is missing.

- [ ] **Step 3: Implement pure visible-row preparation**

Copy matching rows, query liveness by `ProcessInstanceId`, attach the status text, and call the Task 3 sorter. Do not mutate aggregator snapshots.

- [ ] **Step 4: Run tests to verify GREEN**

Expected: all view-state tests pass.

- [ ] **Step 5: Implement the Win32 window and controls**

Register a Unicode window class and create buttons, edit control, report-mode ListView with full-row select/double buffering, and status bar. Add the nine approved columns. Start a one-second timer. On each tick:

1. get a snapshot;
2. build visible rows;
3. preserve selection and scroll position;
4. update/reuse rows keyed by the stable `TrafficKey` stored in an internal row map;
5. update the status bar with running state, ETW lost count, parse failure count, and last error.

Handle button commands, `LVN_COLUMNCLICK`, filter edit changes, resizing, DPI-aware minimum sizing, and `WM_DESTROY`. The clear button calls `TrafficAggregator::Clear`; stop/start never clears totals. `WM_DESTROY` stops the timer and monitor before posting quit.

- [ ] **Step 6: Implement `wWinMain` and manifest integration**

Initialize common controls, enable per-monitor DPI awareness when available with a safe fallback, construct shared aggregator/process cache/monitor objects, create the main window, start collection automatically, and run the message loop. On startup failure, keep the GUI open and show the error in the status bar. Ensure `add_executable(NetAssess WIN32 ...)` embeds `resources/app.manifest` and no console appears.

- [ ] **Step 7: Build Debug, run tests, and commit**

```powershell
git add CMakeLists.txt src/main_window.h src/main_window.cpp src/main.cpp tests/unit_tests.cpp
git commit -m "feat: add native traffic monitor interface"
```

---

### Task 8: Full Verification and Operator Documentation

**Files:**
- Create: `README.md`
- Modify only if a failing test proves a defect: files from Tasks 1-7.

**Interfaces:**
- Documents build, operation, measurement semantics, permissions, supported systems, protocol inference, and known limits.

- [ ] **Step 1: Write operator documentation**

Document the exact PowerShell build commands from this plan, executable path `build/Release/NetAssess.exe`, automatic elevation, controls, columns, IP-byte accounting, one-second speed calculation, and limitations from the spec. Explain that HTTPS/QUIC/etc. are port inferences and that ETW loss makes totals lower bounds when the loss counter is nonzero.

- [ ] **Step 2: Run a clean Debug and Release build**

Remove only the repository-local `build` directory after resolving and verifying its absolute path, then run configure, Debug build, Release build, and CTest.

Expected: both configurations compile and every test passes with no warnings introduced by project code.

- [ ] **Step 3: Perform the elevated GUI integration check**

Run the Release GUI as administrator. Use a PID-known PowerShell process to issue an HTTPS request and a DNS query. Confirm TCP/HTTPS-TLS and UDP/DNS rows appear for that PID, totals increase in the correct direction, rates return to zero, the process becomes ended after exit, clear resets rows, and closing the GUI removes the `NetAssess-*` ETW session.

- [ ] **Step 4: Run final repository checks**

```powershell
git status --short
git diff --check
```

Expected: no unintended files, whitespace errors, build artifacts, or unrelated changes.

- [ ] **Step 5: Commit documentation**

```powershell
git add README.md
git commit -m "docs: explain traffic monitor operation"
```
