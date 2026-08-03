#pragma once

#include <array>
#include <cstdint>
#include <initializer_list>
#include <span>

namespace aegis::seal::detail {

using ByteView = std::span<const std::uint8_t>;
using Digest256 = std::array<std::uint8_t, 32>;
using Digest512 = std::array<std::uint8_t, 64>;

[[nodiscard]] Digest256 hmac_sha256(
    ByteView key,
    std::initializer_list<ByteView> chunks);
[[nodiscard]] Digest512 hmac_sha512(
    ByteView key,
    std::initializer_list<ByteView> chunks);

}  // namespace aegis::seal::detail
