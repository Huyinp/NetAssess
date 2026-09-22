# Task 3 Report — Whole-Server Network Rate Monitor

## RED

Command:

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Debug --target NetAssessTests
```

Output (expected missing-feature failure):

```text
tests\unit_tests.cpp(9,10): error C1083: cannot open include file: 'network_rate_monitor.h': No such file or directory
```

## GREEN

Commands:

```powershell
& .\build\Debug\NetAssessTests.exe
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe' --test-dir build -C Debug --output-on-failure
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Release
```

Results:

```text
NetAssessTests.exe: exit 0
1/1 Test #1: NetAssessTests ... Passed
100% tests passed, 0 tests failed out of 1
Release build: NetAssess.exe and NetAssessTests.exe built successfully
```

The scripted fake tests cover initial zero samples, exact two-second rates,
multi-adapter summation, Down/loopback filtering, new/removed/returned
interfaces, counter rollback, equal/earlier timestamps, and API failure
recovery. A default-adapter smoke test calls `GetIfTable2` on this Windows host.

## Release dependencies

Command:

```powershell
& 'D:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe' /dependents .\build\Release\NetAssessTests.exe
```

`NetAssessTests.exe` imports `tdh.dll`, `IPHLPAPI.DLL`, `ole32.dll`,
`COMCTL32.dll`, `USER32.dll`, `GDI32.dll`, `WS2_32.dll`, and `KERNEL32.dll`.
It imports no `MSVCP*.dll`, `VCRUNTIME*.dll`, or `UCRT*.dll`.

## Self-review

- `GetIfTable2` rows are copied before the `FreeMibTable` RAII guard releases them.
- Baselines change only after successful queries; invalid timestamps, counter rollback,
  nonfinite rates, and API failures retain the prior valid baseline.
- Unsigned counter subtraction happens only after nondecreasing checks; only Up,
  non-loopback interfaces contribute to totals.

## Commit

`feat: measure whole-server network speed`

## Concerns

None. The GUI timer integration is intentionally deferred to Task 7.
