# ASC-1 Specification

## Objective

Build a private Windows-native sealing construction for Aegis. ASC-1 detects changes to normalized relative file entries selected by the caller's approved scope policy by comparing a chained 256-bit seal stored by the caller in the reasoning ledger.

ASC-1 is a low-cost tamper tripwire. It is not a cryptographic security boundary and does not claim resistance to expert reverse engineering or direct use of the local seal generator.

## Confirmed boundaries

- Target: Windows 11 x64.
- Toolchain: C++20, MSVC, CMake, Windows CNG.
- Dependencies: Windows system libraries only.
- Input scope: normalized relative file entries selected and supplied by the caller.
- Output: `ASC1:` followed by 64 lowercase hexadecimal characters.
- Identity: project and run identifiers; no developer identity or developer-held key.
- Hidden material: one ASC-1 release pepper compiled into the native component.
- Failure: malformed input or seal mismatch fails closed; no implicit repair or baseline update.
- Excluded: Git traversal, reasoning-ledger storage, TraceRelay integration, rollback detection, files outside the two core directories, packers, drivers, external services, and production-grade anti-reversing.

## Public data contract

```cpp
struct Context {
    std::array<std::uint8_t, 16> project_id;
    std::array<std::uint8_t, 16> seal_chain_id;
    std::uint64_t sequence;
    std::array<std::uint8_t, 32> previous_seal;
};

struct FileEntry {
    std::string path;
    std::vector<std::uint8_t> content;
};
```

Paths use strict, well-formed UTF-8 bytes and `/`. No Unicode normalization is performed. Entries are sorted by unsigned path bytes inside the core. Duplicate paths, invalid UTF-8, absolute paths, empty paths or segments, `.`, `..`, backslashes, NUL bytes, colons, trailing separators, and empty file sets are rejected. Directory or file-type scope is intentionally outside the core and must be enforced by the caller.

Sequence zero requires an all-zero previous seal. A positive sequence requires a non-zero previous seal.

## ASC-1 construction

The 256-bit release pepper derives four domain-separated keys:

```text
K_leaf  = HMAC-SHA256(pepper, "ASC1/LEAF")
K_left  = HMAC-SHA256(pepper, "ASC1/LEFT")
K_right = HMAC-SHA256(pepper, "ASC1/RIGHT")
K_final = HMAC-SHA256(pepper, "ASC1/FINAL")
```

Each sorted entry produces a 512-bit leaf:

```text
leaf[j] = HMAC-SHA512(
    K_leaf,
    LE32(path_length) || path || LE64(content_length) || content
)
```

Two 512-bit states are initialized and cross-folded. For zero-based file ordinal `j = 0..n-1`, the first file encodes `LE64(0)`:

```text
L[0] = HMAC-SHA512(K_left,  project_id || seal_chain_id)
R[0] = HMAC-SHA512(K_right, LE64(sequence) || previous_seal)

L[j+1] = HMAC-SHA512(
    K_left,
    L[j] || leaf[j] || first16(R[j]) || LE64(j)
)

R[j+1] = HMAC-SHA512(
    K_right,
    R[j] || reverse(leaf[j]) || last16(L[j+1]) || LE64(content_length[j])
)
```

The final 256-bit seal is:

```text
HMAC-SHA256(
    K_final,
    "ASC1" || project_id || seal_chain_id || LE64(sequence) || previous_seal ||
    LE64(file_count) || LE64(total_content_bytes) || L[n] || R[n]
)
```

All integer encodings are fixed-width little-endian. No timestamp, locale, filesystem ordering, or machine-specific path participates.

## API behavior

- `compute_seal(context, entries)` returns 32 bytes or throws `SealError` for invalid input or CNG failure.
- `verify_seal(context, entries, expected)` recomputes and compares all 32 bytes without early exit.
- `format_seal(seal)` returns the canonical `ASC1:<hex>` representation.
- `parse_seal(text)` accepts only the canonical lowercase representation.

## Binary manifest and CLI

The CLI consumes one self-contained binary manifest. Numeric fields are little-endian and the file must end immediately after the final content byte.

```text
8 bytes   magic: 41 53 43 31 4d 46 0d 0a  ("ASC1MF\r\n")
16 bytes  project_id
16 bytes  seal_chain_id
8 bytes   sequence
32 bytes  previous_seal
4 bytes   file_count
repeat file_count times:
    4 bytes   path_length
    N bytes   UTF-8 path
    8 bytes   content_length
    M bytes   raw content
```

Commands and exit codes:

```text
aegis-seal compute <manifest>                  0: seal printed
aegis-seal verify <manifest> <expected-seal>  0: match, 2: mismatch
                                                3: usage or invalid input
```

The component does not traverse Git or the filesystem beyond opening the supplied manifest.

V1 parser limits prevent corrupted length fields from causing unbounded allocation:

- At most 100,000 files.
- At most 32,768 UTF-8 bytes per path.
- At most 256 MiB per file.
- At most 1 GiB total content.

## Project structure

```text
include/aegis_seal/core.hpp  Public in-memory contract
src/core.cpp                 ASC-1 construction and validation
src/cng_hash.cpp             Windows CNG HMAC wrapper
src/pepper.cpp               Private release material reconstruction
src/manifest.cpp             Self-contained binary manifest parser
src/main.cpp                 Minimal native CLI
tests/core_tests.cpp         Behavioral and fixed-vector tests
docs/ASC1_SPEC.md            Normative ASC-1 contract
```

## Testing strategy

- Unit tests: validation, deterministic output, field sensitivity, order normalization, strict UTF-8, formatting, parsing, and fixed parser limits.
- Fixed vector: one canonical vector locks the ASC-1 output across Debug and Release builds.
- Integration test: the compiled CLI computes and verifies a manifest fixture.
- Negative tests: malformed paths and UTF-8, duplicates, invalid chain fields, parser limits and I/O failure, invalid seal text, and mismatched seals.

## Success criteria

- Debug and Release builds succeed with MSVC warnings treated as errors.
- All CTest tests pass in both configurations.
- Identical logical input has identical output regardless of supplied entry order.
- Any tested change to file path, content, project ID, seal-chain ID, sequence, or previous seal changes the output.
- Output differs from raw SHA-256 and truncated SHA-512 of the canonical test payload.
- No third-party dependency, network call, implicit reseal, or fallback acceptance exists.

## Implementation plan

1. Establish the public contract and failing behavioral tests.
2. Add the Windows CNG HMAC wrapper and ASC-1 core until unit tests pass.
3. Lock a fixed vector and add the minimal CLI integration path.
4. Build and test Debug and Release; inspect the produced files and Git diff.

## Deferred work

- Aegis-side Git manifest construction.
- Reasoning-ledger record schema and persistence.
- Public Aegis binary packaging.
- Algorithm rotation and migration from ASC-1.
- External latest-sequence witness for full-repository rollback detection.
