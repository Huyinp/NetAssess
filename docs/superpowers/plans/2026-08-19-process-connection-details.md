# Process Connection Details Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a right-click, live-updating per-process connection window that shows local and remote IPv4/IPv6 endpoints, ports, direction, protocol, totals, and rates without changing the existing process summary.

**Architecture:** Extend the existing TDH layout decoder to emit source and destination addresses, then submit every decoded event to the existing process aggregator and a new bounded connection aggregator. Modeless Win32 connection windows consume immutable per-process snapshots and keep GUI work outside the ETW callback.

**Tech Stack:** C++20, Win32 Unicode API, ETW/TDH, Common Controls ListView, CMake 3.20+, Visual Studio 2022/MSVC x64, CTest.

**Spec:** `docs/superpowers/specs/2026-08-19-process-connection-details-design.md`

## Global Constraints

- Support Windows Server 2016+ Desktop Experience on x64 only.
- Configure with Visual Studio/MSVC and an explicit `-A x64`; retain every existing CMake rejection check.
- Use only Windows API and the C++ standard library; add no GUI framework, packet driver, runtime library, or test framework.
- Keep the executable a Unicode Windows-subsystem GUI with the existing sole `requireAdministrator` manifest entry.
- Application protocols remain port inference only; do not inspect packet contents or perform reverse DNS.
- ETW callbacks perform no GUI work and let no C++ exception cross the Win32 callback boundary.
- Preserve the existing process-summary aggregation and controls.
- Keep connection history until Clear, with a global maximum of exactly `100000` unique connection keys.
- Use saturating `std::uint64_t` counters; never wrap totals or loss/drop counters.
- Treat `EventsLost`, `RealTimeBuffersLost`, parse failures, and detail drops as separate units.
- Retain stable fallback identity for a persistently inaccessible PID and document that such PID reuse cannot always be separated.
- Every production behavior change follows RED-GREEN TDD and receives an independent review before the next task.

---

## File Map

- Modify `src/traffic_types.h`: IP address, endpoint, connection key/event/snapshot value types.
- Modify `src/etw_decoder.h/.cpp`: discover and decode `saddr` and `daddr` for IPv4/IPv6.
- Create `src/connection_aggregator.h/.cpp`: bounded thread-safe connection totals, activity, rates, and Clear.
- Modify `src/etw_monitor.h/.cpp`: coherent loss snapshots and dual-aggregator callback wiring.
- Create `src/connection_view.h/.cpp`: pure display-row construction, text conversion, status/direction, and sorting.
- Create `src/connection_window.h/.cpp`: modeless Win32 connection-detail ListView.
- Modify `src/main_window.h/.cpp`: right-click menu, window registry/lifecycle, Clear, and status text.
- Modify `src/main.cpp`: construct and wire the connection aggregator.
- Modify `src/formatting.h/.cpp`: expose `TransportProtocolName(TransportProtocol)` for both list windows; keep byte/rate formatting unchanged.
- Modify `CMakeLists.txt`: compile and link the two new modules.
- Modify `README.md`: user operation, detail semantics, capacity, loss, and PID limitation.
- Modify `tests/unit_tests.cpp`: deterministic unit and integration coverage through the existing single test executable.

---

### Task 1: Make ETW loss reads coherent and correct the PID limitation

**Files:**
- Modify: `src/etw_monitor.h`
- Modify: `src/etw_monitor.cpp`
- Modify: `src/main_window.cpp`
- Modify: `tests/unit_tests.cpp`
- Modify: `README.md`

**Interfaces:**
- Produces: `struct EtwLossCounters { std::uint64_t events_lost; std::uint64_t real_time_buffers_lost; };`
- Produces: `EtwLossCounters EtwMonitor::loss_counters() const`.
- Retains: `events_lost()` and `real_time_buffers_lost()` as compatibility wrappers returning one field from the coherent result.

- [ ] **Step 1: Strengthen the concurrent QUERY/STOP regression test**

Change the existing `TestEtwMonitorQueriesOwnedLossCountersBeforeConcurrentStop` so QUERY returns `UINT32_MAX`, STOP returns zero, and the query thread stores the value returned by `loss_counters()`. Assert both returned fields are the QUERY values even if STOP stores its final values immediately afterward. Add a loop of at least 100 deterministic interleavings or synchronize each iteration with the existing fake condition variables.

```cpp
EtwLossCounters observed{};
std::jthread query_thread([&] { observed = monitor.loss_counters(); });
// WaitForQuery, start concurrent Stop, then ReleaseQuery.
CHECK_EQ(observed.events_lost, static_cast<std::uint64_t>(UINT32_MAX));
CHECK_EQ(observed.real_time_buffers_lost, 17ULL);
```

- [ ] **Step 2: Run Release test to verify RED**

Run:

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Release --target NetAssessTests
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' --test-dir build -C Release --output-on-failure
```

Expected: compile failure because `EtwLossCounters`/`loss_counters()` do not exist, or the original return-value test intermittently reports zero.

- [ ] **Step 3: Return the queried values while the transition is still protected**

Implement `loss_counters()` so it takes `transition_mutex_`, queries while holding the existing API lock, stores the atomics, copies both query fields into a local `EtwLossCounters`, and returns that local value. If no session exists or QUERY fails, return the currently stored pair. Do not unlock and then reload atomics for the return value. Make both compatibility getters delegate to this method.

Update `MainWindow::UpdateStatus()` to call `loss_counters()` once, so one UI refresh performs one ETW QUERY and displays a coherent pair.

- [ ] **Step 4: Correct README's inaccessible-PID claim**

Replace the false promise that inaccessible PID reuse is detected within eight events. State exactly: full process queries are retried every eight observations; recovery to a readable real creation time is detected; two successive lifetimes that always remain inaccessible may be merged because network events alone contain no process creation time.

- [ ] **Step 5: Verify GREEN and repeat Release execution**

Run the build and CTest commands from Step 2, then run:

```powershell
1..20 | ForEach-Object {
    & '.\build\Release\NetAssessTests.exe'
    if ($LASTEXITCODE -ne 0) { throw "Release repetition $_ failed" }
}
```

Expected: CTest 1/1 passes and all 20 repetitions exit zero.

- [ ] **Step 6: Commit**

```powershell
git add src/etw_monitor.h src/etw_monitor.cpp src/main_window.cpp tests/unit_tests.cpp README.md
git commit -m "fix: return coherent ETW loss counters"
```

---

### Task 2: Decode IPv4 and IPv6 source/destination addresses

**Files:**
- Modify: `src/traffic_types.h`
- Modify: `src/etw_decoder.h`
- Modify: `src/etw_decoder.cpp`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `enum class IpAddressFamily { V4, V6 };`
- Produces: `struct IpAddress { IpAddressFamily family; std::array<std::byte, 16> bytes; auto operator<=>(const IpAddress&) const = default; };`
- Produces: `FieldLayout EventLayout::source_address` and `destination_address` plus `IpAddressFamily EventLayout::address_family`.
- Extends: `DecodedNetworkEvent` with `IpAddress source_address` and `destination_address` before ports.
- Consumes later: the exact decoded addresses without strings or payload pointers.

- [ ] **Step 1: Add failing payload tests**

Add deterministic layouts and byte arrays for:

```cpp
EventLayout ipv4{};
ipv4.pid = {0, 4};
ipv4.size = {4, 4};
ipv4.source_address = {8, 4};
ipv4.destination_address = {12, 4};
ipv4.source_port = {16, 2};
ipv4.destination_port = {18, 2};
ipv4.direction = TrafficDirection::Send;
ipv4.transport = TransportProtocol::Tcp;
ipv4.address_family = IpAddressFamily::V4;

EventLayout ipv6{};
ipv6.pid = {0, 4};
ipv6.size = {4, 4};
ipv6.source_address = {8, 16};
ipv6.destination_address = {24, 16};
ipv6.source_port = {40, 2};
ipv6.destination_port = {42, 2};
ipv6.direction = TrafficDirection::Receive;
ipv6.transport = TransportProtocol::Udp;
ipv6.address_family = IpAddressFamily::V6;
```

Assert all source/destination bytes, family, ports, PID, size, direction, and transport. Add failures for a truncated address and for width/family mismatch. Name tests for behavior, not implementation.

- [ ] **Step 2: Run tests to verify RED**

Run:

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Debug --target NetAssessTests
```

Expected: compile failure because the address types and fields are missing.

- [ ] **Step 3: Implement fixed-size address values and payload decoding**

Add `<array>` and `<cstddef>` to `traffic_types.h`. Copy 4 or 16 payload bytes verbatim into a zero-initialized `IpAddress`; do not reinterpret unaligned storage and do not retain a span. Extend `DecodePayload` bounds checks so any required field failure rejects the whole event.

- [ ] **Step 4: Extend TDH layout discovery**

In `LoadEventLayout`, recognize case-insensitive `saddr` and `daddr`. Derive address family from opcode: the existing IPv4 send/receive opcodes require width 4, the `+16` IPv6 opcodes require width 16. Reject missing, duplicate, variable, or wrong-width address properties only for target send/receive events. Preserve the existing early `Ignored` filter for other provider/opcode/header records.

Add schema-loader tests proving correct fields are cached once and an address-width error increments parse failures for a target event.

- [ ] **Step 5: Verify GREEN**

Run Debug CTest. Expected: 1/1 passes, including all previous ignored/invalid tests.

- [ ] **Step 6: Commit**

```powershell
git add src/traffic_types.h src/etw_decoder.h src/etw_decoder.cpp tests/unit_tests.cpp
git commit -m "feat: decode network endpoint addresses"
```

---

### Task 3: Aggregate bounded per-connection traffic

**Files:**
- Create: `src/connection_aggregator.h`
- Create: `src/connection_aggregator.cpp`
- Modify: `src/traffic_types.h`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `struct NetworkEndpoint { IpAddress address; std::uint16_t port; auto operator<=>(const NetworkEndpoint&) const = default; };`
- Produces: `struct ConnectionKey { ProcessInstanceId process; TransportProtocol transport; ApplicationProtocol application_protocol; NetworkEndpoint local; NetworkEndpoint remote; auto operator<=>(const ConnectionKey&) const = default; };`
- Produces: `struct ConnectionEvent { ConnectionKey key; std::wstring process_name; TrafficDirection direction; std::uint64_t bytes; std::chrono::steady_clock::time_point observed_at; };`
- Produces: `struct ConnectionSnapshot` containing key, process name, sent/received totals and rates, and `last_activity`.
- Produces: `ConnectionAggregator(std::size_t max_entries = 100000)`, `void Add(const ConnectionEvent&)`, `std::vector<ConnectionSnapshot> Snapshot(ProcessInstanceId, time_point)`, `void ResetSnapshotBaseline(ProcessInstanceId)`, `void Clear()`, and `std::uint64_t dropped_detail_events() const`.

- [ ] **Step 1: Write failing aggregation tests**

Cover:

- send and receive with the same canonical endpoints merge into one key;
- same IP/different port and same port/different IP remain separate;
- TCP/UDP, application protocol, and process instance remain separate;
- sent/received saturation independently reaches `UINT64_MAX`;
- first snapshot is zero rate, a known two-second interval produces exact rates, no bytes produces zero, invalid time does not corrupt the baseline;
- `last_activity` advances only to the latest observation;
- `ResetSnapshotBaseline(process)` makes the next snapshot for that process zero rate;
- a test aggregator with `max_entries = 2` rejects a third unique key, increments the saturated drop-event counter, continues updating the first key, and Clear resets entries/baselines/drops.

- [ ] **Step 2: Run tests to verify RED**

Expected: compile failure because `connection_aggregator.h` is missing.

- [ ] **Step 3: Implement the minimal bounded aggregator**

Use one `std::map<ConnectionKey, Entry>` and one mutex. On Add, find before checking capacity so existing keys always update. If a new key arrives at capacity, saturating-increment `dropped_detail_events_` and return. Store per-entry previous counters and use a per-process previous snapshot time map so snapshots for different open windows do not affect one another.

`Snapshot(process, now)` must copy only matching process entries. Update baselines only for that process and only on initial or strictly later time, matching `TrafficAggregator`'s corrected invalid-time behavior.

- [ ] **Step 4: Add the module to CMake and verify GREEN**

Add `src/connection_aggregator.cpp` to `NetAssessCore`. Build Debug and run CTest; expected 1/1 pass.

- [ ] **Step 5: Commit**

```powershell
git add src/traffic_types.h src/connection_aggregator.h src/connection_aggregator.cpp CMakeLists.txt tests/unit_tests.cpp
git commit -m "feat: aggregate bounded connection traffic"
```

---

### Task 4: Wire the real ETW callback to both aggregators

**Files:**
- Modify: `src/etw_monitor.h`
- Modify: `src/etw_monitor.cpp`
- Modify: `src/main.cpp`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `EtwMonitor(TrafficAggregator&, ConnectionAggregator&, ProcessInfoCache&)`.
- Produces: `EtwMonitor(TrafficAggregator&, ConnectionAggregator&, ProcessInfoCache&, IEtwSessionApi&)`.
- Produces: `EtwMonitor(TrafficAggregator&, ConnectionAggregator&, ProcessInfoCache&, IEtwSessionApi&, EtwDecoder::SchemaLoader)`.
- Produces: pure `ConnectionKey BuildConnectionKey(ProcessInstanceId, TransportProtocol, ApplicationProtocol, TrafficDirection, IpAddress source, std::uint16_t source_port, IpAddress destination, std::uint16_t destination_port)` declared in `connection_aggregator.h`.
- Preserves existing Start/Stop, callback exception containment, loss, and session ownership semantics.

- [ ] **Step 1: Write a failing actual-callback integration test**

Use `FakeEtwSessionApi::InvokeEventCallback`, an injected schema loader, and `FakeProcessInfoApi`. Construct one synthetic IPv4 TCP send `EVENT_RECORD`, call the actual callback captured by `OpenTraceW`, then assert:

```cpp
const auto process_rows = traffic_aggregator.Snapshot(t0);
const auto detail_rows = connection_aggregator.Snapshot(process_id, t0);
CHECK_EQ(process_rows.size(), 1ULL);
CHECK_EQ(detail_rows.size(), 1ULL);
CHECK_EQ(detail_rows[0].key.local.port, source_port);
CHECK_EQ(detail_rows[0].key.remote.port, destination_port);
CHECK_EQ(detail_rows[0].sent_bytes, packet_size);
```

Add a receive record with reversed event endpoints and assert it merges into the same connection row and increments received bytes. This test must not manually call Decode/Resolve/Infer/Add in test code.

- [ ] **Step 2: Run tests to verify RED**

Expected: constructor mismatch or detail snapshot remains empty because the monitor does not know the connection aggregator.

- [ ] **Step 3: Implement canonical endpoint conversion and dual submission**

Resolve process and infer application protocol once. Submit the unchanged process-level `TrafficEvent`. Canonicalize endpoints using send `local=source, remote=destination` and receive `local=destination, remote=source`, then submit `ConnectionEvent` with one captured `steady_clock::now()`.

Update every production and test construction of `EtwMonitor` with a real `ConnectionAggregator`; do not add nullable pointers or optional feature flags.

- [ ] **Step 4: Verify callback safety and GREEN**

Run Debug CTest. Also retain the callback-throws test and assert an exception from either aggregator path is contained, sets `ERROR_UNHANDLED_EXCEPTION`, and requests stop without joining the consumer thread.

- [ ] **Step 5: Commit**

```powershell
git add src/etw_monitor.h src/etw_monitor.cpp src/main.cpp tests/unit_tests.cpp
git commit -m "feat: collect connection-level traffic"
```

---

### Task 5: Build connection display rows and sorting

**Files:**
- Create: `src/connection_view.h`
- Create: `src/connection_view.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `enum class ConnectionActivityStatus { Active, Historical, ProcessEnded };`
- Produces: `enum class ConnectionDirection { SendOnly, ReceiveOnly, Bidirectional };`
- Produces: `struct ConnectionDisplayRow { ConnectionSnapshot connection; bool process_alive; ConnectionActivityStatus status; ConnectionDirection direction; };`
- Produces: `std::wstring FormatIpAddress(const IpAddress&)` using `InetNtopW` from `ws2_32`, which is available on Windows Server 2016.
- Produces: `std::wstring_view TransportProtocolName(TransportProtocol)` in `formatting.h/.cpp`, replacing the main-window-private duplicate.
- Produces: `std::wstring_view ConnectionActivityStatusText(ConnectionActivityStatus)` and `std::wstring_view ConnectionDirectionName(ConnectionDirection)`.
- Produces: `enum class ConnectionSortColumn` for all 12 columns plus `CombinedSpeed`.
- Produces: `std::vector<ConnectionDisplayRow> BuildConnectionRows(const std::vector<ConnectionSnapshot>&, bool process_alive, std::chrono::steady_clock::time_point now, ConnectionSortColumn sort_column = ConnectionSortColumn::CombinedSpeed, bool ascending = false)`.
- Produces: `void SortConnectionRows(std::vector<ConnectionDisplayRow>&, ConnectionSortColumn, bool ascending)`.

- [ ] **Step 1: Write failing view-model tests**

Test IPv4 `192.0.2.1`, compressed IPv6 `2001:db8::1`, send/receive/bidirectional direction, active at exactly five seconds, historical after five seconds, and ProcessEnded overriding activity. Test each numeric key type and default combined-speed descending order. For equal values, fall back to the full `ConnectionKey` for deterministic ordering.

- [ ] **Step 2: Run tests to verify RED**

Expected: compile failure because `connection_view.h` is missing.

- [ ] **Step 3: Implement pure row construction and invariant comparisons**

Use `InetNtopW(AF_INET/AF_INET6, ...)` from `<ws2tcpip.h>` and link `ws2_32`. Return `L"无效地址"` only on formatting failure. Compare process names with `CompareStringOrdinal(..., TRUE)` and addresses through their binary key, never formatted text. Move the existing TCP/UDP display helper to `TransportProtocolName` and update the main window to call it.

- [ ] **Step 4: Verify GREEN and CMake**

Add `src/connection_view.cpp` to `NetAssessCore`, build Debug, and run CTest. Expected: 1/1 pass.

- [ ] **Step 5: Commit**

```powershell
git add src/connection_view.h src/connection_view.cpp CMakeLists.txt tests/unit_tests.cpp
git commit -m "feat: present connection detail rows"
```

---

### Task 6: Add the modeless Win32 connection window and right-click menu

**Files:**
- Create: `src/connection_window.h`
- Create: `src/connection_window.cpp`
- Modify: `src/main_window.h`
- Modify: `src/main_window.cpp`
- Modify: `src/main.cpp`
- Modify: `CMakeLists.txt`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Produces: `HWND CreateConnectionWindow(HINSTANCE, HWND owner, ProcessInstanceId, std::wstring process_name, ConnectionAggregator&, ProcessInfoCache&)`.
- Changes: `CreateMainWindow` receives `ConnectionAggregator&` between `TrafficAggregator&` and `ProcessInfoCache&`.
- MainWindow owns `std::map<ProcessInstanceId, HWND> connection_windows_` on the UI thread.

- [ ] **Step 1: Add a failing pure row-selection test**

Declare `std::optional<ProcessInstanceId> ProcessForVisibleRow(std::span<const TrafficKey> current_keys, int row)` in `main_window.h`. Assert two protocol rows for one process return the same instance, different creation times remain distinct, and negative/out-of-range rows return `std::nullopt`. Keep HWND create-versus-activate behavior inside `MainWindow`; do not introduce a general window framework solely to mock `IsWindow`.

- [ ] **Step 2: Run tests to verify RED**

Expected: compile failure because the selection helper or connection-window API is missing.

- [ ] **Step 3: Implement the connection window**

Create one focused Win32 class containing a report ListView with the 12 specified columns. Use the existing runtime DPI helpers or move only those helpers into a small shared internal header if both window modules require identical code; do not refactor unrelated main-window behavior.

On its one-second timer:

```cpp
auto snapshots = aggregator_.Snapshot(process_, std::chrono::steady_clock::now());
auto rows = BuildConnectionRows(snapshots,
    process_cache_.RefreshAlive(process_), now, sort_column_, ascending_);
```

Reconcile rows by stable `ConnectionKey`, preserving selection and scroll anchor like the main ListView. On creation call `ResetSnapshotBaseline(process_)` so the first displayed speeds are zero. Closing the window destroys only its UI.

- [ ] **Step 4: Implement main-list context handling**

Handle `NM_RCLICK` (and keyboard `WM_CONTEXTMENU`) only for a valid data row. Show a popup menu containing `查看连接明细`. Resolve the row's `ProcessInstanceId`, remove stale `!IsWindow` registry entries, activate an existing detail window with `ShowWindow`/`SetForegroundWindow`, or create and register a new one.

On Clear, call both aggregators' `Clear`; open detail windows remain and become empty on their next refresh. On main `WM_DESTROY`, destroy every registered detail window before stopping the monitor. Add `明细丢弃：N` to the status bar.

- [ ] **Step 5: Wire construction and build**

In `main.cpp`, construct in lifetime order:

```cpp
TrafficAggregator traffic_aggregator;
ConnectionAggregator connection_aggregator;
ProcessInfoCache process_cache;
EtwMonitor monitor(traffic_aggregator, connection_aggregator, process_cache);
HWND window = CreateMainWindow(instance, traffic_aggregator,
                               connection_aggregator, process_cache, monitor);
```

Add `src/connection_window.cpp` to `NetAssessCore`. Build Debug and Release; run CTest for both.

- [ ] **Step 6: Perform static GUI checks**

Verify `dumpbin /headers build/Release/NetAssess.exe` reports x64 and Windows GUI. Extract the manifest with `mt.exe` and confirm exactly one `requireAdministrator` plus Common Controls v6. Verify no optional DPI API became a static import that would break Server 2016.

- [ ] **Step 7: Commit**

```powershell
git add src/connection_window.h src/connection_window.cpp src/main_window.h src/main_window.cpp src/main.cpp CMakeLists.txt tests/unit_tests.cpp
git commit -m "feat: show per-process connection details"
```

---

### Task 7: Document, stress-test, and prepare live acceptance

**Files:**
- Modify: `README.md`
- Modify only if a failing test proves a defect: files from Tasks 1-6.

**Interfaces:**
- Documents the finished operator workflow and limitations; produces no new code interface.

- [ ] **Step 1: Update README**

Document right-click opening, one window per process instance, all 12 columns, local/remote direction rules, IPv4/IPv6 formatting, five-second Active/Historical meaning, ProcessEnded, default/column sorting, Clear behavior, 100000-key cap, detail-drop status, connection-key reuse, port-only protocol inference, separate loss counters, and the corrected persistently inaccessible PID limitation.

- [ ] **Step 2: Run a clean x64 build**

Resolve the worktree root and exact repository-local `build` path. Delete only that validated `build` directory, then run:

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' -S . -B build -A x64
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Debug
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Release
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Debug --target RUN_TESTS
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' --test-dir build -C Release --output-on-failure
```

Expected: both builds succeed without project warnings; Debug and Release CTest each report 1/1 passed.

- [ ] **Step 3: Repeat Release tests for concurrency confidence**

Run `build/Release/NetAssessTests.exe` 50 times in a PowerShell loop and fail on any nonzero exit. Expected: 50/50 zero exits, specifically no ETW loss QUERY/STOP assertion failure.

- [ ] **Step 4: Verify binary and repository state**

Check x64/Windows GUI headers, embedded manifest, optional DPI imports, `git diff --check`, `git status --short`, and that build artifacts remain ignored. Expected: only the intended README modification is uncommitted before the documentation commit.

- [ ] **Step 5: Write the manual acceptance record**

In the task report, include exact steps and an explicit PASS/NOT RUN result for: IPv4/IPv6 HTTPS, UDP DNS, correct endpoints and ports, bidirectional merge, rate rise/zero, five-second historical transition, process exit, two simultaneous detail windows, repeated open activation, column sort, DPI resizing, Clear, all four loss/drop counters, and no `NetAssess-*` session after exit. Never claim live GUI success if UAC/native-window automation was not actually performed.

- [ ] **Step 6: Commit documentation**

```powershell
git add README.md
git commit -m "docs: explain connection detail monitoring"
```

- [ ] **Step 7: Request whole-branch review**

Review the full range from `ed0235c` to HEAD against the approved spec, including all deferred/manual items. Any Critical or Important issue must be fixed and re-reviewed before integration choices are offered.
