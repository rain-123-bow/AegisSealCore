# AegisSealCore

## Scope

- Windows 11 x64 only.
- C++20, MSVC, CMake, Windows CNG.
- Produce a deterministic ASC-1 sealing core and a small native CLI.
- The caller supplies normalized relative file entries selected by its approved scope policy.

## Commands

```powershell
$cmake = 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $cmake -S . -B build -G 'Visual Studio 18 2026' -A x64
& $cmake --build build --config Debug
& $cmake --build build --config Release
& $cmake --build build --config Debug --target RUN_TESTS
```

## Rules

- Keep the ASC-1 byte encoding deterministic and versioned.
- Add or update tests before changing behavior.
- Reject malformed input; never repair or reseal it implicitly.
- Do not add third-party dependencies, network access, services, packers, or drivers.
- Do not claim resistance to expert reverse engineering.
- Do not commit build directories, debug symbols, or generated binaries unless explicitly requested.
