#include "pepper.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace aegis::seal::detail {
namespace {

constexpr std::uint8_t rotate_left8(const std::uint8_t value, const unsigned int shift) {
    const auto amount = shift & 7U;
    return static_cast<std::uint8_t>(
        static_cast<unsigned int>(value) << amount |
        static_cast<unsigned int>(value) >> ((8U - amount) & 7U));
}

}  // namespace

__declspec(noinline) ReleasePepper release_pepper() noexcept {
    static volatile std::uint8_t fragment_a[32]{
        0xbc, 0x20, 0x40, 0x23, 0x67, 0x45, 0x88, 0x8e,
        0xcb, 0xbe, 0xec, 0x76, 0x76, 0xdb, 0x2e, 0x5b,
        0x3a, 0xa1, 0xdf, 0x04, 0x7a, 0x12, 0xae, 0x07,
        0xdf, 0xef, 0x08, 0x84, 0x6c, 0x6a, 0x28, 0x5b,
    };
    static volatile std::uint8_t fragment_b[32]{
        0xba, 0x69, 0xb6, 0xd4, 0x70, 0xd6, 0xae, 0xf4,
        0x27, 0xb5, 0xba, 0x8b, 0x38, 0xb6, 0xc9, 0x8d,
        0x40, 0x3b, 0x88, 0x1e, 0x1c, 0x46, 0x73, 0x24,
        0xf1, 0x4b, 0x1f, 0x7a, 0xbf, 0xab, 0xc3, 0x1c,
    };

    ReleasePepper result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto left = fragment_a[index];
        const auto right = fragment_b[(index * 7U + 11U) % result.size()];
        const auto mask = static_cast<std::uint8_t>(0x5dU + index * 0x13U);
        result[index] = rotate_left8(
            static_cast<std::uint8_t>(left ^ right ^ mask),
            static_cast<unsigned int>((index % 7U) + 1U));
    }
    return result;
}

}  // namespace aegis::seal::detail
