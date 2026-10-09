# Memory Integrity Inspector

*A lightweight, open-source Windows memory inspection utility written in C++17.*

Memory Integrity Inspector is a small, standalone C++17 command-line utility for examining the virtual memory metadata of a selected Windows x64 process. It reports executable mappings, private executable allocations, and writable executable regions using documented Windows APIs. It does not read or dump memory contents.

## Key features

- Explicit PID selection and strict argument validation.
- Committed-region enumeration with `VirtualQueryEx`.
- Current and allocation protection flags, addresses, exact byte sizes, state, and mapping type for each executable finding.
- Transparent INFO, REVIEW, and SUSPICIOUS classifications without threat scores.
- Detailed findings or a condensed summary without retaining per-region findings.
- Checked address arithmetic, forward progress, process lifetime checks, and explicit partial results.
- Automatic process-handle cleanup, monochrome terminal output, and no third-party dependencies.

## Detection indicators

Classification uses the current protection's low-byte base value, separately from modifiers such as `PAGE_GUARD`. Only `MEM_COMMIT` regions with one of `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, or `PAGE_EXECUTE_WRITECOPY` qualify as executable. Reserved, free, non-executable, and unrecognized base protections do not generate findings.

| Observable property | Classification | Interpretation |
| --- | --- | --- |
| `PAGE_EXECUTE_READWRITE`, any mapping type | SUSPICIOUS | Current base protection permits simultaneous read, write, and execute access. |
| Executable `MEM_PRIVATE`, without direct RWX | REVIEW | Private executable allocation; legitimate runtimes also create these. |
| Executable `MEM_MAPPED`, without direct RWX | REVIEW | Executable file mapping; review its origin and intended use. |
| Executable `MEM_IMAGE`, without direct RWX | INFO | Executable image mapping, provided as context. |
| Executable region with an unknown mapping type, without direct RWX | REVIEW | Executable metadata whose mapping type is unrecognized. |

Each executable region produces one finding at the highest applicable classification. A private RWX region contributes one SUSPICIOUS finding, and its detail also identifies private executable memory. Mapping-type statistics count executable regions independently of severity; finding counts are mutually exclusive.

`PAGE_EXECUTE_WRITECOPY` is executable copy-on-write protection. It is displayed explicitly and is not counted as direct RWX. Writes can create a private writable executable copy. `VirtualQueryEx` can continue reporting modified copy-on-write pages as `MEM_IMAGE` or `MEM_MAPPED`; this utility does not inspect page sharing or prove that code was modified.

`PAGE_GUARD` indicates a one-shot access alarm. Findings describe the underlying base permissions, not whether an immediate guarded access would succeed. Querying metadata does not read guarded pages or clear the guard. Cache, write-combine, and CFG modifiers are displayed separately; raw hexadecimal flags preserve other bits and ambiguous aliases.

## Technical overview

`OpenProcess` requests only `PROCESS_QUERY_INFORMATION | SYNCHRONIZE`: the former is required by `VirtualQueryEx` and the architecture query; the latter enables reliable zero-timeout process termination checks with `WaitForSingleObject`. The process handle is non-inheritable and managed with RAII. No `PROCESS_VM_READ`, write, thread-creation, or all-access rights are requested. No privileges are enabled, and there is no elevation or protection bypass.

The scanner verifies that the target is a native x64 process, then walks from address zero through the native system's maximum application address. Free and reserved ranges advance traversal but do not enter committed-region statistics. Every query must return a complete structure and a nonzero region size with the expected base address and a checked, increasing end address. Unexpected results stop traversal instead of skipping unknown ranges. Committed-byte accumulation is also checked for overflow.

The target is checked before each query and again before reporting completion. Query failures, process termination, and invalid boundaries produce Failed or Partial status and a nonzero exit code. Previously collected findings remain visible on a partial traversal. A completed scan means traversal finished while the target was observed running; it is not an atomic or immutable snapshot. Summary mode uses the same queries and classifications but does not retain individual findings.

Documented API references: [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex), [memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants), and [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).

## Project structure

```text
Memory-Integrity-Inspector/
├── main.cpp
├── memory_scanner.cpp
├── memory_scanner.h
├── CMakeLists.txt
├── build.bat
└── README.md
```

`main.cpp` handles arguments and presentation. `memory_scanner.cpp` handles queries, classification, and protection formatting. `memory_scanner.h` contains the small shared interface. `build.bat` locates the installed tools and builds the project with CMake. No third-party runtime dependencies or services are required.

## Build requirements

- Windows 10 or Windows 11 on x64 hardware.
- Visual Studio 2022 or its Build Tools with Desktop development with C++, including an MSVC x64 compiler and Windows SDK.
- CMake 3.20 or newer.
- C++17 support.

The MSVC build statically links the C++ runtime so the Release executable can be distributed alone. Debug builds are intended for development. x86 and ARM64 builds and WOW64 target processes are outside the supported scope.

## Quick Build

Install the build requirements above, then double-click `build.bat` in the project root. It locates Visual Studio 2022's MSVC x64 tools and CMake, configures the project, and builds the Release executable. CMake can be on `PATH`, in its standard installation directory, or bundled with Visual Studio 2022.

You can also run it directly from PowerShell:

```powershell
.\build.bat
```

From CMD, run `build.bat`. The script pauses at the end so the result remains visible when double-clicked. For automation or a terminal command that returns immediately after the build, use:

```powershell
.\build.bat --no-pause
```

The script works independently of the current working directory. All generated files go into a sibling directory named after the source folder with `-build` appended. With the project structure shown above, the output is `..\Memory-Integrity-Inspector-build\Release\Memory-Integrity-Inspector.exe`. Its full path is printed after a successful build.

The build script returns `0` on success, `2` for missing tools or invalid arguments, and the CMake exit code if configuration or compilation fails. A missing executable after an otherwise successful build returns `1`. Missing SDKs or an unsupported CMake version are reported during configuration. The script does not install dependencies, request elevation, or download packages.

## Build with CMake

To build manually, run from the repository root in PowerShell. The build directory is a sibling of the source directory, keeping generated files outside the six-file repository.

```powershell
cmake -S . -B ..\Memory-Integrity-Inspector-build -G "Visual Studio 17 2022" -A x64
cmake --build ..\Memory-Integrity-Inspector-build --config Release
```

The executable is `..\Memory-Integrity-Inspector-build\Release\Memory-Integrity-Inspector.exe`. No package download, network access, or dependency installation is performed by the CMake project.

## Usage

```powershell
..\Memory-Integrity-Inspector-build\Release\Memory-Integrity-Inspector.exe --help
..\Memory-Integrity-Inspector-build\Release\Memory-Integrity-Inspector.exe --pid 1234
..\Memory-Integrity-Inspector-build\Release\Memory-Integrity-Inspector.exe --pid 1234 --summary
```

Replace `1234` with the PID of a native x64 process you are authorized to inspect. `--pid` accepts a nonzero decimal value within the unsigned 32-bit range. `--summary` may precede or follow `--pid`. Duplicate options, extra arguments, missing values, signed values, hexadecimal values, and overflow are rejected. `--help` must appear alone.

Detailed mode lists all executable findings in ascending address order, then statistics. Summary mode prints the target, counts, byte totals, completion status, and any failure details. Numeric Windows error codes accompany API failures. Access-denied results are expected for some targets; the utility does not circumvent them.

| Exit code | Meaning |
| --- | --- |
| 0 | Help displayed or traversal completed, regardless of finding severity. |
| 1 | Inspection failed, target unsupported, or an unexpected application error occurred. |
| 2 | Invalid command-line arguments. |
| 3 | Traversal started but could not finish; statistics cover only inspected ranges. |

## Example console output

The following is an illustrative summary, not a captured scan or validation result. Actual output is derived from Windows queries and varies with the target and time of inspection.

```text
============================================================
                 MEMORY INTEGRITY INSPECTOR
                   Windows x64 Research
============================================================
Target PID          : 1234
Status              : Inspecting process memory
------------------------------------------------------------
Regions Queried     : 420
Regions Inspected   : 180 committed
Committed Bytes     : 33554432
Executable IMAGE    : 40
Executable MAPPED   : 0
Executable PRIVATE  : 2
Executable OTHER    : 0
Info Findings       : 40
Review Findings     : 1
Suspicious Findings : 1
Status              : Completed
Detail              : Address-space traversal completed; observations are not an atomic snapshot.
Findings describe memory properties, not proof of malware or cheating.
============================================================
```

## Security limitations and false positives

- Suspicious memory does not establish malware, cheating, injection, or malicious intent. JIT compilers, browsers, runtime environments, debuggers, and legitimate security software can create private executable or RWX memory.
- INFO does not certify an image as trusted, and an absence of findings does not certify process integrity. The utility does not verify image signatures, compare memory to disk, inspect instructions, or identify allocation owners.
- Results reflect queried virtual-memory metadata. They do not measure resident physical memory, actual execution, page-level sharing, or historical protection changes.
- Running processes can allocate, release, or reprotect memory during traversal. There is no process suspension, consistent snapshot, or guarantee of catching transient regions. Detected query or boundary failures are reported explicitly; undetectable concurrent changes can still affect observations.
- Protected, inaccessible, exited, and unsupported processes may fail inspection. A held handle prevents a later PID reuse from switching the already-opened target, but selection races before `OpenProcess` remain possible.
- The utility has no memory modification, remote threads, DLL injection, patching, privilege escalation, anti-debug bypass, kernel component, memory dumping, YARA, automatic background scanning, telemetry, external networking, or backend integration.

## Supported Windows versions

Windows 10 x64 and Windows 11 x64, with native x64 target processes. Availability of access to any particular process is governed by Windows security and the caller's existing permissions. Windows Server and Windows on ARM are not claimed as supported targets.

## Disclaimer

This utility is provided for authorized defensive security research, education, and diagnostics. Interpret findings in the context of the target application's legitimate behavior. It is not a reliable malware or cheat detector and must not be the sole basis for enforcement decisions. Use only on systems and processes you are authorized to inspect.
