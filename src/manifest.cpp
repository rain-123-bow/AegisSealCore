#include "manifest.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <istream>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>

namespace aegis::seal::detail {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic{
    0x41, 0x53, 0x43, 0x31, 0x4d, 0x46, 0x0d, 0x0a,
};

void read_exact(std::istream& input, std::uint8_t* destination, const std::size_t size) {
    if (size == 0) {
        return;
    }
    if (size > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw SealError{"ASC-1 manifest field exceeds stream limits"};
    }
    input.read(
        reinterpret_cast<char*>(destination), static_cast<std::streamsize>(size));
    if (!input) {
        throw SealError{"ASC-1 manifest is truncated"};
    }
}

template <std::size_t Size>
void read_exact(std::istream& input, std::array<std::uint8_t, Size>& output) {
    read_exact(input, output.data(), output.size());
}

template <typename Integer>
Integer read_little_endian(std::istream& input) {
    static_assert(std::is_unsigned_v<Integer>);
    std::array<std::uint8_t, sizeof(Integer)> encoded{};
    read_exact(input, encoded);
    Integer value = 0;
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        value |= static_cast<Integer>(encoded[index]) << (index * 8U);
    }
    return value;
}

std::string read_path(
    std::istream& input,
    const std::uint32_t size,
    const ManifestLimits& limits) {
    if (size == 0 || size > limits.max_path_bytes) {
        throw SealError{"ASC-1 manifest path length is invalid"};
    }
    std::string path(size, '\0');
    read_exact(
        input, reinterpret_cast<std::uint8_t*>(path.data()), path.size());
    return path;
}

std::vector<std::uint8_t> read_content(
    std::istream& input,
    const std::uint64_t size,
    std::uint64_t& total_size,
    const ManifestLimits& limits) {
    if (size > limits.max_content_bytes ||
        size > limits.max_total_content_bytes ||
        total_size > limits.max_total_content_bytes - size) {
        throw SealError{"ASC-1 manifest content exceeds v1 limits"};
    }
    if (size > std::numeric_limits<std::size_t>::max()) {
        throw SealError{"ASC-1 manifest content exceeds process limits"};
    }
    total_size += size;
    std::vector<std::uint8_t> content(static_cast<std::size_t>(size));
    read_exact(input, content.data(), content.size());
    return content;
}

}  // namespace

Manifest read_manifest(std::istream& input, const ManifestLimits& limits) {
    try {
        std::array<std::uint8_t, kMagic.size()> magic{};
        read_exact(input, magic);
        if (magic != kMagic) {
            throw SealError{"ASC-1 manifest magic is invalid"};
        }

        Manifest manifest{};
        read_exact(input, manifest.context.project_id);
        read_exact(input, manifest.context.run_id);
        manifest.context.sequence = read_little_endian<std::uint64_t>(input);
        read_exact(input, manifest.context.previous_seal);

        const auto file_count = read_little_endian<std::uint32_t>(input);
        if (file_count == 0 || file_count > limits.max_file_count) {
            throw SealError{"ASC-1 manifest file count is invalid"};
        }
        manifest.entries.reserve(file_count);

        std::uint64_t total_content_bytes = 0;
        for (std::uint32_t index = 0; index < file_count; ++index) {
            const auto path_size = read_little_endian<std::uint32_t>(input);
            auto path = read_path(input, path_size, limits);
            const auto content_size = read_little_endian<std::uint64_t>(input);
            auto content = read_content(
                input, content_size, total_content_bytes, limits);
            manifest.entries.push_back(FileEntry{
                .path = std::move(path),
                .content = std::move(content),
            });
        }

        const auto trailing = input.peek();
        if (input.bad()) {
            throw SealError{"ASC-1 manifest tail read failed"};
        }
        if (trailing != std::char_traits<char>::eof()) {
            throw SealError{"ASC-1 manifest contains trailing bytes"};
        }
        return manifest;
    } catch (const SealError&) {
        throw;
    } catch (const std::exception& error) {
        throw SealError{std::string{"ASC-1 manifest read failed: "} + error.what()};
    }
}

}  // namespace aegis::seal::detail
