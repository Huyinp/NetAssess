# Operational UI Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe process actions, connection IP/port filters, CSV export, visible sort direction, stable user-controlled scrolling, and whole-server network speed to NetAssess.

**Architecture:** Keep ETW aggregation unchanged. Add focused Windows boundary modules for process actions and adapter counters, pure model helpers for filters/CSV/scroll intent, then wire those modules into the two existing Win32 windows. The existing one-second main timer remains the only refresh timer.

**Tech Stack:** C++20, Win32, Common Controls v6, IP Helper API, CMake/Visual Studio 2022, x64 Windows Server 2016+ Desktop Experience.

**Spec:** `docs/superpowers/specs/2026-09-22-process-actions-filters-export-network-rate-design.md`

## Global Constraints

- Support Windows Server 2016 and later Desktop Experience, x64 only.
- Preserve `requireAdministrator`, Common Controls v6, the Windows GUI subsystem, and `/MT` (`/MTd` for Debug).
- Use only Windows system libraries; do not add third-party dependencies or worker threads.
- Keep the ETW process/connection aggregation model, single main one-second timer, stable row keys, 12 connection columns, and PID-plus-creation-time process identity.
- CSV exports exactly the current filtered and sorted rows in the visible column order, encoded as UTF-8 with BOM.
- Whole-server speed includes Up physical and virtual interfaces and excludes software loopback interfaces.
- Process termination affects only the selected process, after confirmation and process-instance revalidation; it never recursively terminates children.
- Use `apply_patch` for source edits and strict RED/GREEN TDD for behavioral changes.

## Review Focus

- A PID reused between menu display and confirmation must never terminate or reveal the replacement process; Task 4 tests creation-time mismatch.
- Adapter hot-plug, reconnect, counter rollback, and zero/negative elapsed time must not create a speed spike; Task 3 tests each transition.
- A CSV cell containing Chinese text, comma, quote, CR, or LF must round-trip according to RFC-style quoting; Task 1 uses literal byte expectations.
- Programmatic ListView reconciliation must not mark the list as manually scrolled; Task 5 distinguishes internal and user scroll messages.
- Filters that remove the selected or top row must leave valid selection/top state without stale indices; Tasks 2, 6, and 7 use disappearing-row fixtures.

---

### Task 1: Shared CSV Encoding and File Export

**Files:**
- Create: `src/csv_export.h`
- Create: `src/csv_export.cpp`
- Modify: `CMakeLists.txt`
- Test: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: `std::span<const std::wstring>` column headers and `std::span<const std::vector<std::wstring>>` rows.
- Produces: `struct CsvBuildResult { std::string bytes; DWORD error; };`; `CsvBuildResult BuildCsvUtf8(...)`; `DWORD WriteCsvFile(std::wstring_view path, std::string_view bytes)`; `struct CsvSaveResult { bool saved; DWORD error; };`; `CsvSaveResult SaveCsvWithDialog(HWND owner, std::wstring_view default_name, ...)`.

- [ ] **Step 1: Write failing CSV encoding tests**

Add literal expectations that cover an empty table, Chinese text, commas, quotes, CR/LF, and uneven input rows rejected with `ERROR_INVALID_DATA` through a result-returning helper. The primary fixture must include:

```cpp
const std::vector<std::wstring> headers{L"进程名", L"说明"};
const std::vector<std::vector<std::wstring>> rows{
    {L"程序.exe", L"逗号,引号\"和\r\n换行"},
};
const CsvBuildResult csv = BuildCsvUtf8(headers, rows);
CHECK_EQ(csv.error, ERROR_SUCCESS);
CHECK_TRUE(csv.bytes.starts_with("\xEF\xBB\xBF"));
CHECK_TRUE(csv.bytes.find("\"逗号,引号\"\"和\r\n换行\"") != std::string::npos);
```

- [ ] **Step 2: Run the focused test and verify RED**

Run the Debug build and `build\Debug\NetAssessTests.exe`. Expected: compile failure because `BuildCsvUtf8` is absent, or the new named CSV tests fail for missing behavior.

- [ ] **Step 3: Implement minimal CSV encoding and file writing**

Implement exact UTF-8 BOM output, CRLF records, quote doubling, field quoting, complete-write checks, and `FlushFileBuffers`/`CloseHandle` error preservation. Use `GetSaveFileNameW` with `.csv` default extension; cancellation (`CommDlgExtendedError() == 0`) returns `{false, ERROR_SUCCESS}`.

- [ ] **Step 4: Verify GREEN and the real file boundary**

Run the focused CSV tests, then the full Debug test executable. Add a temporary-file test that reads exact bytes back and removes only its own file.

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt src/csv_export.h src/csv_export.cpp tests/unit_tests.cpp
git commit -m "feat: add shared CSV export"
```

### Task 2: Connection IP and Port Filtering

**Files:**
- Modify: `src/connection_view.h`
- Modify: `src/connection_view.cpp`
- Test: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: `ConnectionDisplayRow`, formatted local/remote IP, local/remote numeric ports.
- Produces: `struct ConnectionFilter { std::wstring ip; std::optional<std::uint16_t> port; };`; `struct PortFilterParseResult { std::optional<std::uint16_t> port; bool valid; };`; `PortFilterParseResult ParsePortFilter(std::wstring_view)`; `FilterConnectionRows(std::vector<ConnectionDisplayRow>, const ConnectionFilter&)`.

- [ ] **Step 1: Write failing filter tests**

Use three literal IPv4/IPv6 rows and assert empty filters retain all rows, IP substrings match either endpoint without case sensitivity, port matches local or remote, combined filters require both conditions, `0` and `65535` parse, and whitespace, signs, suffixes, and `65536` are invalid.

```cpp
CHECK_EQ(ParsePortFilter(L"443").port, std::optional<std::uint16_t>{443});
CHECK_TRUE(!ParsePortFilter(L"443x").valid);
CHECK_TRUE(!ParsePortFilter(L"65536").valid);
```

- [ ] **Step 2: Run focused tests and verify RED**

Run `build\Debug\NetAssessTests.exe`. Expected: compile failure or named filter assertions fail because the interfaces do not exist.

- [ ] **Step 3: Implement parsing and filtering**

Parse decimal digits with checked accumulation and no locale-dependent conversion. Reuse `CompareStringOrdinal(..., TRUE)` semantics for IP substring matching. Preserve input order so the caller's existing sort remains authoritative.

- [ ] **Step 4: Verify GREEN**

Run the focused filter tests and full Debug suite.

- [ ] **Step 5: Commit**

```powershell
git add src/connection_view.h src/connection_view.cpp tests/unit_tests.cpp
git commit -m "feat: filter connection details"
```

### Task 3: Whole-Server Network Rate Monitor

**Files:**
- Create: `src/network_rate_monitor.h`
- Create: `src/network_rate_monitor.cpp`
- Modify: `CMakeLists.txt`
- Test: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: IP Helper adapter rows normalized to `NetworkInterfaceCounters { uint64_t interface_luid; IF_OPER_STATUS status; NET_IFTYPE type; uint64_t in_octets; uint64_t out_octets; }` and `steady_clock::time_point`.
- Produces: `struct NetworkRateSnapshot { double received_bytes_per_second; double sent_bytes_per_second; DWORD error; };`; `class INetworkInterfaceApi { virtual DWORD Query(std::vector<NetworkInterfaceCounters>&) = 0; };`; `class NetworkRateMonitor { NetworkRateSnapshot Snapshot(time_point now); }` with default and injected API constructors.

- [ ] **Step 1: Write failing rate-state tests**

Use a fake API with literal samples to prove: first sample zero; 1000 receive/500 send over two seconds yields 500/250 B/s; two adapters sum independently; Down and `IF_TYPE_SOFTWARE_LOOPBACK` rows are excluded; a new interface starts at zero; removed interfaces lose their baselines; rollback and equal/earlier timestamps yield zero without corrupting a later valid baseline; API failure returns the exact error and does not mutate baselines.

- [ ] **Step 2: Run focused tests and verify RED**

Run `build\Debug\NetAssessTests.exe`. Expected: compile failure because the monitor is absent.

- [ ] **Step 3: Implement IP Helper enumeration and rate state**

Use `GetIfTable2`/`FreeMibTable` from `iphlpapi`, `MIB_IF_ROW2::InterfaceLuid`, `OperStatus`, `Type`, `InOctets`, and `OutOctets`. Filter Up rows and software loopback. Calculate per-interface deltas with the actual positive elapsed time and finite nonnegative results, then sum. Replace the retained baseline only after a successful query.

- [ ] **Step 4: Verify GREEN and Windows linkage**

Run focused tests and full Debug suite. Build Release and use `dumpbin /dependents` to confirm only Windows system DLLs, including `IPHLPAPI.dll`, are imported.

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt src/network_rate_monitor.h src/network_rate_monitor.cpp tests/unit_tests.cpp
git commit -m "feat: measure whole-server network speed"
```

### Task 4: Safe Process Actions

**Files:**
- Create: `src/process_actions.h`
- Create: `src/process_actions.cpp`
- Modify: `CMakeLists.txt`
- Test: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: the selected `ProcessInstanceId` and display name.
- Produces: `struct ProcessActionResult { bool succeeded; DWORD error; };`; `class IProcessActionApi` with process open, creation-time, image-path, shell-launch, terminate, and close boundaries; `class ProcessActions` with `RevealExecutable(ProcessInstanceId)` and `Terminate(ProcessInstanceId)`; default and injected API constructors.

- [ ] **Step 1: Write failing process-action tests**

Fake every Windows boundary. Assert reveal and terminate both re-read creation time and act only on an exact process-instance match. Assert reveal uses the queried full path and passes Explorer a `/select,` argument with correct quoting; terminate opens with only required rights, closes every acquired handle, and returns exact errors for open/query/path/shell/terminate failures. Include creation-time mismatch fixtures asserting zero shell-launch and zero terminate calls.

- [ ] **Step 2: Run focused tests and verify RED**

Run `build\Debug\NetAssessTests.exe`. Expected: compile failure or missing behavior failures.

- [ ] **Step 3: Implement the Windows boundary and instance guard**

Query path with `PROCESS_QUERY_LIMITED_INFORMATION`; terminate with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE`; use `GetProcessTimes`, `QueryFullProcessImageNameW`, `ShellExecuteExW` for Explorer `/select,`, and `TerminateProcess`. Map zero/ambiguous errors to `ERROR_GEN_FAILURE`. Never reveal or terminate on creation-time mismatch; return `ERROR_NOT_FOUND`.

- [ ] **Step 4: Verify GREEN**

Run focused tests and full Debug suite. Inspect that no test invokes real `TerminateProcess`.

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt src/process_actions.h src/process_actions.cpp tests/unit_tests.cpp
git commit -m "feat: add safe process actions"
```

### Task 5: Shared ListView Sort Indicators and Scroll Intent

**Files:**
- Create: `src/list_view_state.h`
- Create: `src/list_view_state.cpp`
- Modify: `CMakeLists.txt`
- Test: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: a ListView/header HWND, active column, direction, user input notification/message, stable row keys, and current top index.
- Produces: `void UpdateListViewSortIndicator(HWND, int column, bool ascending)`; `class ListScrollState` with `ResetToAutoTop()`, `ObserveUserScroll(bool at_top)`, `bool auto_top() const`, and a guard that distinguishes programmatic restoration from user input. Each owning window preserves its own typed stable top key.

- [ ] **Step 1: Write failing pure-state and hidden-control tests**

Assert initial auto-top, manual departure disables it, manual return enables it, sort/filter reset enables it, and programmatic restoration leaves the state unchanged. Create a hidden report ListView with three columns and assert only the selected header contains `HDF_SORTUP` or `HDF_SORTDOWN`, switching column clears the previous flags.

- [ ] **Step 2: Run focused tests and verify RED**

Run `build\Debug\NetAssessTests.exe`. Expected: compile failure because the helper is absent.

- [ ] **Step 3: Implement minimal header and state helpers**

Use `Header_GetItem`/`Header_SetItem` and preserve unrelated `HDITEM::fmt` bits. Keep user-scroll detection in the owning window subclasses, calling the pure state helper only for actual wheel, scrollbar, and navigation-key input. Guard programmatic reconciliation with an internal boolean.

- [ ] **Step 4: Verify GREEN**

Run focused tests and full Debug suite, including Common Controls initialization inside the hidden-control fixture.

- [ ] **Step 5: Commit**

```powershell
git add CMakeLists.txt src/list_view_state.h src/list_view_state.cpp tests/unit_tests.cpp
git commit -m "feat: track list sorting and scroll intent"
```

### Task 6: Connection Detail Window Integration

**Files:**
- Modify: `src/connection_window.cpp`
- Modify: `src/connection_view.h`
- Modify: `src/connection_view.cpp`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: Task 1 CSV functions, Task 2 filters, Task 5 sort/scroll helpers, existing `BuildConnectionRows` and stable `ConnectionKey` reconciliation.
- Produces: a resizable detail toolbar with IP filter, port filter, and export button; current filtered/sorted row model available to export.

- [ ] **Step 1: Write failing connection-window integration tests**

Create a hidden detail window and submit multiple literal connection rows. Drive `WM_COMMAND` for IP/port edits and assert visible row keys; enter invalid `443x` and assert the previous valid filter remains active plus an error is reported through a test-capturable message boundary. Drive `LVN_COLUMNCLICK` and assert header direction and top index. Simulate manual wheel/scroll then refresh and assert the same stable top key; return to top, refresh, and assert top remains zero. Verify the export row builder returns all current filtered/sorted rows rather than only visible indices.

- [ ] **Step 2: Run focused tests and verify RED**

Run `build\Debug\NetAssessTests.exe`. Expected: hidden-window assertions fail because controls and behavior are absent.

- [ ] **Step 3: Add toolbar layout, filtering, export, arrows, and scroll behavior**

Create controls during `WM_CREATE`, use existing font/DPI helpers, relayout on size and `WM_DPICHANGED`, and preserve early Win32 creation errors. Apply filter before sort/reconcile. Export the same `rows_` in the 12 visible-column order. Subclass only the detail ListView and remove the subclass during destruction.

- [ ] **Step 4: Verify GREEN**

Run the focused integration tests and full Debug suite. Resize the hidden window across two DPI-equivalent dimensions and assert every control remains within the client rectangle.

- [ ] **Step 5: Commit**

```powershell
git add src/connection_window.cpp src/connection_view.h src/connection_view.cpp tests/unit_tests.cpp
git commit -m "feat: add connection filters and CSV export"
```

### Task 7: Main Window Process Menu, CSV, Network Status, and List Behavior

**Files:**
- Modify: `src/main_window.cpp`
- Modify: `src/main_window.h`
- Modify: `src/main.cpp`
- Modify: `tests/unit_tests.cpp`

**Interfaces:**
- Consumes: Tasks 1, 3, 4, and 5; existing `BuildVisibleRows`, `ProcessForVisibleRow`, one-second timer, and status bar.
- Produces: three-item row context menu, export button, whole-server rate status, visible sort indicators, and stable user scroll behavior.

- [ ] **Step 1: Write failing main-window integration tests**

Inject fake process actions and network interface samples through explicit overloads or constructor dependencies. On a hidden main window, assert context commands use the right `ProcessInstanceId`; cancellation prevents terminate; confirmation invokes exactly one terminate; mismatch/error text includes the exact code. Assert CSV rows match the current name filter and sort. Advance fake adapter counters and timer refresh, then assert status text contains independently formatted up/down/total rates. Repeat sort-arrow and manual-scroll scenarios from Task 6 against `TrafficKey` stable rows.

- [ ] **Step 2: Run focused tests and verify RED**

Run `build\Debug\NetAssessTests.exe`. Expected: hidden-window assertions fail because menu commands, export control, network status, and list behavior are absent.

- [ ] **Step 3: Integrate process actions and CSV export**

Add menu IDs for reveal and terminate, retain the right-clicked stable process instance, display one confirmation dialog containing name and PID, call the injected/default `ProcessActions`, and show exact Windows errors. Add and lay out the export button; export all rows in the nine visible-column order.

- [ ] **Step 4: Integrate network status and list state**

Own one `NetworkRateMonitor` in the main window or inject one for tests. Sample it once per existing timer tick and append `总网速：↑ ... ↓ ... 合计 ...` to the status bar. On sampling failure show `总网速：不可用（错误 <code>）` without a modal. Add sort indicators and manual-scroll preservation through Task 5 helpers.

- [ ] **Step 5: Verify GREEN**

Run focused integration tests and the complete Debug suite. Confirm clear statistics does not reset adapter counter baselines, while window recreation does.

- [ ] **Step 6: Commit**

```powershell
git add src/main_window.cpp src/main_window.h src/main.cpp tests/unit_tests.cpp
git commit -m "feat: add main-window operational tools"
```

### Task 8: Documentation, Clean Build, and Release Acceptance

**Files:**
- Modify: `README.md`
- Test: `tests/unit_tests.cpp` only if final integration exposes an uncovered behavior; do not add source-text tests.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: user documentation, verified Release executable, and a distributable ZIP containing `NetAssess.exe` plus `README.md`.

- [ ] **Step 1: Update user documentation**

Document the three context-menu actions, single-process termination confirmation/instance guard, IP and port filter syntax, current-view CSV semantics and UTF-8 BOM, sort arrows and scroll behavior, whole-server adapter scope, loopback exclusion, and error behavior. State that process actions require sufficient Windows rights.

- [ ] **Step 2: Perform a clean two-configuration build**

Configure with the Visual Studio generator and explicit `-A x64`. Build Debug and Release from a clean task-local build directory. Run CTest for both configurations with `--output-on-failure`.

- [ ] **Step 3: Verify release properties**

Use `dumpbin /headers`, `/dependents`, and manifest/string inspection to confirm x64 PE32+ Windows GUI, `requireAdministrator`, Common Controls v6, no MSVCP/VCRUNTIME/UCRT DLL dependency, and only expected Windows system DLLs including IP Helper.

- [ ] **Step 4: Run bounded manual acceptance when the environment permits**

On an elevated Windows Server 2016+ Desktop Experience host: reveal this program's EXE; launch and terminate a dedicated harmless test process; verify failure against a protected process without changing it; generate physical/virtual adapter traffic; exercise mouse, scrollbar, and keyboard scrolling in both windows; export both CSV files and open them in Excel. Record every item as PASS, FAIL, or NOT RUN; never convert an environment limitation into a pass.

- [ ] **Step 5: Package and commit**

Create `build/NetAssess-win64-<short-head>.zip` containing the verified Release `NetAssess.exe` and `README.md`. Keep build artifacts ignored. Commit only tracked documentation or required test corrections.

```powershell
git add README.md tests/unit_tests.cpp
git commit -m "docs: explain operational UI tools"
```

- [ ] **Step 6: Request final whole-branch review**

Review from the branch merge base through HEAD, explicitly checking every Global Constraint and Review Focus item. If findings exist, use one consolidated final fix wave and one scoped re-review before presenting branch integration options.
