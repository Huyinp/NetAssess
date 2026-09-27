# Process Cache and Retention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce per-event process-query overhead and keep long-running traffic data bounded without deleting idle processes that are still running.

**Architecture:** Add monotonic-time throttling to `ProcessInfoCache`, carry one ETW observation timestamp into both aggregators, and let the main window coordinate a ten-minute, seven-day retention sweep outside aggregator locks. Preserve the 100,000 connection cap, but admit new connections by evicting an oldest eligible 5% batch when capacity pressure occurs.

**Tech Stack:** C++20, Win32, ETW, CMake/MSVC, existing custom unit-test executable.

**Spec:** `docs/superpowers/specs/2026-09-27-process-cache-retention-design.md`

## Global Constraints

- Use `std::chrono::steady_clock` for every interval and cutoff comparison.
- Keep Windows process queries outside aggregator locks.
- Preserve PID plus creation-time identity and the existing boolean UI liveness behavior.
- Treat process-query failure as unknown during retention; never delete on an unknown result.
- Keep the default connection capacity at 100,000 and all byte/drop counters saturating.
- Do not add settings, configuration files, or unrelated refactors.
- After each task, run the focused test executable before committing.

## Review Focus

- Boundary semantics: intervals become due at `>= 1s`, retention becomes eligible only when the newest activity is strictly older than seven days, and capacity eviction requires activity strictly older than five seconds.
- PID reuse: a changed creation time must replace the cached instance after the throttle interval.
- Cleanup consistency: removal must cover traffic rows, connection rows, and connection snapshot baselines.
- Capacity edge cases: zero capacity, fewer eligible rows than the batch target, deterministic equal-time ordering, and all-active saturation.
- UI query count: one liveness lookup per `ProcessInstanceId` per main-list refresh.

---

## Task 1: Throttle process identity validation by elapsed time

**Files:**

- Modify: `src/process_info.h`
- Modify: `src/process_info.cpp`
- Modify: `tests/unit_tests.cpp`

- [ ] Add failing tests that call `Resolve` repeatedly with explicit `steady_clock::time_point` values and assert: no creation-time query before one second, one query exactly at one second, unchanged identity on matching creation time, and replacement identity after PID reuse.
- [ ] Add failing tests showing that creation-time failures and restricted-process full-query retries occur at most once per second, independent of event count.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm the new tests fail for the expected missing API/behavior.
- [ ] Change the public signature to:

  ```cpp
  ProcessInfo Resolve(std::uint32_t pid,
                      std::uint64_t fallback_observation_id,
                      std::chrono::steady_clock::time_point now);
  ```

- [ ] Replace observation-count retry state with timestamps. Store `last_validation` for successful PID cache entries and `last_attempt` for fallback entries. Within one second, return the cached value without calling the process API; at or after one second, validate once and update the timestamp even when validation fails.
- [ ] Preserve the current consecutive-failure tolerance and fallback identity behavior; only change when attempts occur.
- [ ] Update existing direct callers in tests to pass explicit timestamps.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm all tests pass.
- [ ] Commit with message `perf: throttle process identity validation`.

## Task 2: Carry one observation time through ETW and traffic aggregation

**Files:**

- Modify: `src/traffic_types.h`
- Modify: `src/etw_monitor.cpp`
- Modify: `src/traffic_aggregator.h`
- Modify: `src/traffic_aggregator.cpp`
- Modify: `tests/unit_tests.cpp`

- [ ] Add failing tests proving that `TrafficAggregator::Add` records the newest `TrafficEvent::observed_at` for each entry, including out-of-order older events not moving activity backward.
- [ ] Extend the existing ETW `EventSubmitter` capture test to assert that the traffic event and connection event produced from one decoded ETW event receive the same observation timestamp. Keep the implementation to one local timestamp passed to `Resolve` and both event constructors rather than adding a new clock abstraction.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm the focused tests fail.
- [ ] Add `std::chrono::steady_clock::time_point observed_at` to `TrafficEvent` and `last_activity` to `TrafficAggregator::Entry`.
- [ ] In the ETW callback, obtain `steady_clock::now()` once after decoding, pass it to `ProcessInfoCache::Resolve`, and use it for both emitted events.
- [ ] Update traffic aggregation with `last_activity = max(last_activity, event.observed_at)` while preserving byte and rate behavior.
- [ ] Update existing test fixtures and non-ETW callers to provide deterministic timestamps.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm all tests pass.
- [ ] Commit with message `feat: track traffic activity timestamps`.

## Task 3: Add tri-state probing and retention operations

**Files:**

- Modify: `src/process_info.h`
- Modify: `src/process_info.cpp`
- Modify: `src/traffic_aggregator.h`
- Modify: `src/traffic_aggregator.cpp`
- Modify: `src/connection_aggregator.h`
- Modify: `src/connection_aggregator.cpp`
- Modify: `tests/unit_tests.cpp`

- [ ] Extend `IProcessInfoApi` with `ProbeProcess(ProcessInstanceId)` returning a new `enum class ProcessProbeResult { Running, Ended, Unknown };`, then add failing fake-API tests showing that `ProcessInfoCache::ProbeAlive` preserves all three results. Keep `RefreshAlive` compatible with current UI tests.
- [ ] Add failing aggregator tests for these interfaces:

  ```cpp
  std::vector<ProcessInstanceId> ProcessesInactiveBefore(
      std::chrono::steady_clock::time_point cutoff) const;
  void RemoveProcesses(std::span<const ProcessInstanceId> processes);
  ```

  Verify candidates are decided from each process's newest activity across all of its rows, the exact cutoff is not prematurely eligible, and removal clears all rows for the selected process only.
- [ ] Add a connection-aggregator test proving `RemoveProcesses` also clears `previous_snapshot_times_` by taking a snapshot, removing the process, adding it again, and observing a fresh zero-rate baseline.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm the new tests fail.
- [ ] Implement the Windows probe by opening the PID with limited query access, comparing creation time, and checking process exit state. Return `Ended` only for a confirmed absent/exited process or identity mismatch; return `Unknown` for access and query failures. Make `ProcessInfoCache::ProbeAlive` delegate to the API and retain `RefreshAlive` as the existing display-oriented boolean wrapper.
- [ ] Implement both aggregators' candidate and removal methods under short-lived locks. Mark a process inactive only when its maximum `last_activity` is strictly less than the cutoff.
- [ ] Clear connection snapshot baselines for every removed process.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm all tests pass.
- [ ] Commit with message `feat: add process retention operations`.

## Task 4: Evict old connection details under capacity pressure

**Files:**

- Modify: `src/connection_aggregator.h`
- Modify: `src/connection_aggregator.cpp`
- Modify: `tests/unit_tests.cpp`

- [ ] Add failing tests with small capacities showing that a new unique connection at capacity evicts the oldest entries strictly older than `event.observed_at - 5s`, admits the new event, and evicts up to `max(1, max_entries / 20)` eligible entries.
- [ ] Add failing tests for fewer eligible entries than the batch size, equal activity times with deterministic `ConnectionKey` tie-breaking, zero capacity, and a fully active table that drops the new event and saturating-increments `dropped_detail_events()`.
- [ ] Add a test proving an evicted process with no remaining connections loses its speed baseline, while a process with another connection keeps its baseline.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm the tests fail.
- [ ] Add a private locked helper that selects eligible entries by `(last_activity, ConnectionKey)`, erases the oldest batch, and removes baselines only for processes no longer present.
- [ ] Invoke eviction only when adding a new key at capacity. If no entry is eligible, preserve the current drop-and-count behavior; if capacity is zero, drop without scanning.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm all tests pass.
- [ ] Commit with message `feat: evict stale connection details at capacity`.

## Task 5: Schedule seven-day cleanup and deduplicate UI liveness checks

**Files:**

- Modify: `src/main_window.h`
- Modify: `src/main_window.cpp`
- Modify: `tests/unit_tests.cpp`

- [ ] Extend `MainWindowDependencies` with narrowly scoped injectable hooks for the monotonic clock and retention probe, leaving production defaults intact. Add tests that drive refreshes before and at the ten-minute schedule boundary.
- [ ] Add failing window tests proving: cleanup does not run early; candidates from both aggregators are unioned and deduplicated; an old `Running` or `Unknown` process remains; an old `Ended` process is removed from both aggregators and its connection baseline; and the cleanup deadline advances after a run.
- [ ] Add a failing `BuildVisibleRows` test with multiple TCP/UDP/application rows for the same process and assert the supplied `alive_lookup` is called once for that `ProcessInstanceId` during one invocation.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm the new tests fail.
- [ ] Add a private next-cleanup deadline initialized to ten minutes after window creation. On due refresh, gather candidates using `now - 7 days`, union them by `ProcessInstanceId`, probe each candidate once outside aggregator locks, and pass only confirmed-ended IDs to both removal methods.
- [ ] Cache `alive_lookup` results locally inside `BuildVisibleRows`, keyed by `ProcessInstanceId`, so the cache expires after each refresh.
- [ ] Keep normal one-second UI refresh, filtering, sorting, scroll behavior, and status totals unchanged.
- [ ] Run `build\Debug\NetAssessTests.exe` and confirm all tests pass.
- [ ] Commit with message `feat: clean expired process traffic`.

## Task 6: Document, verify, review, and package

**Files:**

- Modify: `README.md`
- Generated: `build/NetAssess-win64-<commit>.zip`

- [ ] Update the README to state the one-second process-validation window, ten-minute cleanup cadence, seven-day retention rule, running/unknown preservation, and capacity-pressure eviction behavior.
- [ ] Configure/build Debug x64 if needed, then run:

  ```powershell
  & 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Debug
  & 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' --test-dir build -C Debug --output-on-failure
  ```

- [ ] Build and test Release with the same commands using `--config Release` and `-C Release`.
- [ ] Inspect the Release executable architecture and imported DLLs; confirm x64 and no accidental debug-runtime dependency.
- [ ] Review the complete diff against the spec and the Review Focus list. Remove only dead code introduced by these changes.
- [ ] Commit documentation with message `docs: describe cache and retention behavior`.
- [ ] Create `build/NetAssess-win64-<short-commit>.zip` from the final Release executable plus required runtime/readme files, then calculate and record its SHA-256.
- [ ] Run the Release test suite once more after the final commit and report the executable path, ZIP path, commit, tests, and hash.
