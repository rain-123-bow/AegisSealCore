#pragma once

#include "aegis_seal/core.hpp"

#include <cstdint>
#include <istream>
#include <vector>

namespace aegis::seal::detail {

struct Manifest {
    Context context;
    std::vector<FileEntry> entries;
};

struct ManifestLimits {
    std::uint32_t max_file_count;
    std::uint32_t max_path_bytes;
    std::uint64_t max_content_bytes;
    std::uint64_t max_total_content_bytes;
};

inline constexpr ManifestLimits kV1ManifestLimits{
    .max_file_count = 100'000,
    .max_path_bytes = 32'768,
    .max_content_bytes = 256ULL * 1024ULL * 1024ULL,
    .max_total_content_bytes = 1024ULL * 1024ULL * 1024ULL,
};

[[nodiscard]] Manifest read_manifest(
    std::istream& input,
    const ManifestLimits& limits = kV1ManifestLimits);

}  // namespace aegis::seal::detail
