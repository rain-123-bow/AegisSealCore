# AegisSealCore

Private source for the Windows-native ASC-1 sealing component used by Aegis.

ASC-1 deterministically binds normalized `src/**` and `include/**` entries to project, run, sequence, and previous-seal context. It is a low-cost tamper tripwire, not a production cryptographic security boundary.

## Build and test

```powershell
$cmake = 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
& $cmake -S . -B build -G 'Visual Studio 18 2026' -A x64
& $cmake --build build --config Debug --target RUN_TESTS
& $cmake --build build --config Release --target RUN_TESTS
```

Release binary:

```text
build/Release/aegis-seal.exe
```

## CLI

```text
aegis-seal compute <manifest>
aegis-seal verify <manifest> <ASC1:seal>
```

The manifest format, algorithm contract, limits, and explicit security boundary are defined in `docs/ASC1_SPEC.md`.
