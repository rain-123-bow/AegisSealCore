#include "aegis_seal/core.hpp"

#include "cng_hash.hpp"
#include "pepper.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace aegis::seal {
namespace {

using detail::ByteView;
using detail::Digest256;
using detail::Digest512;

template <std::size_t Size>
ByteView bytes(const std::array<std::uint8_t, Size>& value) {
    return ByteView{value.data(), value.size()};
}

ByteView bytes(const std::vector<std::uint8_t>& value) {
    return ByteView{value.data(), value.size()};
}

ByteView bytes(const std::string_view value) {
    return ByteView{
        reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

std::array<std::uint8_t, 4> little_endian32(const std::uint32_t value) {
    std::array<std::uint8_t, 4> output{};
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
    return output;
}

std::array<std::uint8_t, 8> little_endian64(const std::uint64_t value) {
    std::array<std::uint8_t, 8> output{};
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = static_cast<std::uint8_t>(value >> (index * 8U));
    }
    return output;
}

bool all_zero(const Seal& value) {
    return std::all_of(value.begin(), value.end(), [](const auto byte) {
        return byte == 0;
    });
}

bool unsigned_path_less(const std::string& left, const std::string& right) {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end(),
        [](const char lhs, const char rhs) {
            return static_cast<unsigned char>(lhs) < static_cast<unsigned char>(rhs);
        });
}

bool is_utf8_continuation(const std::uint8_t byte) {
    return byte >= 0x80U && byte <= 0xbfU;
}

void validate_utf8(const std::string_view value) {
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = static_cast<std::uint8_t>(value[index]);
        if (first <= 0x7fU) {
            ++index;
            continue;
        }

        const auto available = value.size() - index;
        if (first >= 0xc2U && first <= 0xdfU) {
            if (available < 2U ||
                !is_utf8_continuation(static_cast<std::uint8_t>(value[index + 1U]))) {
                throw SealError{"ASC-1 path is not valid UTF-8"};
            }
            index += 2U;
            continue;
        }

        if (first >= 0xe0U && first <= 0xefU) {
            if (available < 3U) {
                throw SealError{"ASC-1 path is not valid UTF-8"};
            }
            const auto second = static_cast<std::uint8_t>(value[index + 1U]);
            const auto third = static_cast<std::uint8_t>(value[index + 2U]);
            const bool second_is_valid =
                (first == 0xe0U && second >= 0xa0U && second <= 0xbfU) ||
                (first >= 0xe1U && first <= 0xecU && is_utf8_continuation(second)) ||
                (first == 0xedU && second >= 0x80U && second <= 0x9fU) ||
                (first >= 0xeeU && first <= 0xefU && is_utf8_continuation(second));
            if (!second_is_valid || !is_utf8_continuation(third)) {
                throw SealError{"ASC-1 path is not valid UTF-8"};
            }
            index += 3U;
            continue;
        }

        if (first >= 0xf0U && first <= 0xf4U) {
            if (available < 4U) {
                throw SealError{"ASC-1 path is not valid UTF-8"};
            }
            const auto second = static_cast<std::uint8_t>(value[index + 1U]);
            const auto third = static_cast<std::uint8_t>(value[index + 2U]);
            const auto fourth = static_cast<std::uint8_t>(value[index + 3U]);
            const bool second_is_valid =
                (first == 0xf0U && second >= 0x90U && second <= 0xbfU) ||
                (first >= 0xf1U && first <= 0xf3U && is_utf8_continuation(second)) ||
                (first == 0xf4U && second >= 0x80U && second <= 0x8fU);
            if (!second_is_valid ||
                !is_utf8_continuation(third) ||
                !is_utf8_continuation(fourth)) {
                throw SealError{"ASC-1 path is not valid UTF-8"};
            }
            index += 4U;
            continue;
        }

        throw SealError{"ASC-1 path is not valid UTF-8"};
    }
}

void validate_path(const std::string& path) {
    if (path.empty() || path.starts_with('/') || path.ends_with('/')) {
        throw SealError{"ASC-1 path is not a normalized relative file path: " + path};
    }
    if (path.find('\\') != std::string::npos ||
        path.find('\0') != std::string::npos ||
        path.find(':') != std::string::npos) {
        throw SealError{"ASC-1 path contains a forbidden character: " + path};
    }
    validate_utf8(path);

    std::size_t segment_start = 0;
    while (segment_start < path.size()) {
        const auto separator = path.find('/', segment_start);
        const auto segment_end = separator == std::string::npos ? path.size() : separator;
        const auto segment = std::string_view{path}.substr(
            segment_start, segment_end - segment_start);
        if (segment.empty() || segment == "." || segment == "..") {
            throw SealError{"ASC-1 path contains an invalid segment: " + path};
        }
        if (separator == std::string::npos) {
            break;
        }
        segment_start = separator + 1U;
    }
}

Digest256 derive_key(const detail::ReleasePepper& pepper, const std::string_view label) {
    return detail::hmac_sha256(bytes(pepper), {bytes(label)});
}

struct DerivedKeys {
    Digest256 leaf;
    Digest256 left;
    Digest256 right;
    Digest256 final;
};

DerivedKeys derive_keys() {
    const auto pepper = detail::release_pepper();
    return DerivedKeys{
        .leaf = derive_key(pepper, "ASC1/LEAF"),
        .left = derive_key(pepper, "ASC1/LEFT"),
        .right = derive_key(pepper, "ASC1/RIGHT"),
        .final = derive_key(pepper, "ASC1/FINAL"),
    };
}

void validate_context(const Context& context) {
    if (context.sequence == 0 && !all_zero(context.previous_seal)) {
        throw SealError{"ASC-1 sequence zero requires a zero previous seal"};
    }
    if (context.sequence > 0 && all_zero(context.previous_seal)) {
        throw SealError{"ASC-1 positive sequence requires a previous seal"};
    }
}

Seal compute_seal_impl(const Context& context, const std::vector<FileEntry>& entries) {
    validate_context(context);
    if (entries.empty()) {
        throw SealError{"ASC-1 requires at least one file entry"};
    }

    std::vector<const FileEntry*> sorted_entries;
    sorted_entries.reserve(entries.size());
    for (const auto& entry : entries) {
        validate_path(entry.path);
        sorted_entries.push_back(&entry);
    }
    std::sort(sorted_entries.begin(), sorted_entries.end(), [](const auto* left, const auto* right) {
        return unsigned_path_less(left->path, right->path);
    });
    for (std::size_t index = 1; index < sorted_entries.size(); ++index) {
        if (sorted_entries[index - 1]->path == sorted_entries[index]->path) {
            throw SealError{"ASC-1 contains a duplicate path: " + sorted_entries[index]->path};
        }
    }

    const auto keys = derive_keys();
    auto left = detail::hmac_sha512(
        bytes(keys.left), {bytes(context.project_id), bytes(context.seal_chain_id)});
    const auto sequence = little_endian64(context.sequence);
    auto right = detail::hmac_sha512(
        bytes(keys.right), {bytes(sequence), bytes(context.previous_seal)});

    std::uint64_t total_content_bytes = 0;
    for (std::size_t index = 0; index < sorted_entries.size(); ++index) {
        const auto& entry = *sorted_entries[index];
        if (entry.path.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw SealError{"ASC-1 path exceeds the encoded length limit"};
        }
        if (entry.content.size() > std::numeric_limits<std::uint64_t>::max() - total_content_bytes) {
            throw SealError{"ASC-1 total content length overflow"};
        }
        total_content_bytes += static_cast<std::uint64_t>(entry.content.size());

        const auto path_length = little_endian32(
            static_cast<std::uint32_t>(entry.path.size()));
        const auto content_length = little_endian64(
            static_cast<std::uint64_t>(entry.content.size()));
        const auto leaf = detail::hmac_sha512(
            bytes(keys.leaf),
            {bytes(path_length), bytes(entry.path), bytes(content_length), bytes(entry.content)});
        const auto entry_index = little_endian64(static_cast<std::uint64_t>(index));
        const ByteView right_prefix{right.data(), 16};
        const auto next_left = detail::hmac_sha512(
            bytes(keys.left), {bytes(left), bytes(leaf), right_prefix, bytes(entry_index)});

        auto reversed_leaf = leaf;
        std::reverse(reversed_leaf.begin(), reversed_leaf.end());
        const ByteView left_suffix{next_left.data() + 48, 16};
        const auto next_right = detail::hmac_sha512(
            bytes(keys.right),
            {bytes(right), bytes(reversed_leaf), left_suffix, bytes(content_length)});
        left = next_left;
        right = next_right;
    }

    constexpr std::string_view version = "ASC1";
    const auto file_count = little_endian64(
        static_cast<std::uint64_t>(sorted_entries.size()));
    const auto total_size = little_endian64(total_content_bytes);
    return detail::hmac_sha256(
        bytes(keys.final),
        {bytes(version), bytes(context.project_id), bytes(context.seal_chain_id), bytes(sequence),
         bytes(context.previous_seal), bytes(file_count), bytes(total_size), bytes(left),
         bytes(right)});
}

std::uint8_t hex_value(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    throw SealError{"ASC-1 seal contains a non-canonical hexadecimal character"};
}

}  // namespace

Seal compute_seal(const Context& context, const std::vector<FileEntry>& entries) {
    try {
        return compute_seal_impl(context, entries);
    } catch (const SealError&) {
        throw;
    } catch (const std::exception& error) {
        throw SealError{std::string{"ASC-1 computation failed: "} + error.what()};
    }
}

bool verify_seal(
    const Context& context,
    const std::vector<FileEntry>& entries,
    const Seal& expected) {
    const auto actual = compute_seal(context, entries);
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        difference = static_cast<std::uint8_t>(
            difference | static_cast<std::uint8_t>(actual[index] ^ expected[index]));
    }
    return difference == 0;
}

std::string format_seal(const Seal& seal) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output{"ASC1:"};
    output.reserve(5U + seal.size() * 2U);
    for (const auto byte : seal) {
        output.push_back(digits[byte >> 4U]);
        output.push_back(digits[byte & 0x0fU]);
    }
    return output;
}

Seal parse_seal(const std::string_view text) {
    constexpr std::string_view prefix = "ASC1:";
    constexpr std::size_t encoded_size = 5U + Seal{}.size() * 2U;
    if (text.size() != encoded_size || !text.starts_with(prefix)) {
        throw SealError{"ASC-1 seal has an invalid prefix or length"};
    }

    Seal output{};
    for (std::size_t index = 0; index < output.size(); ++index) {
        const auto high = hex_value(text[prefix.size() + index * 2U]);
        const auto low = hex_value(text[prefix.size() + index * 2U + 1U]);
        output[index] = static_cast<std::uint8_t>((high << 4U) | low);
    }
    return output;
}

}  // namespace aegis::seal
