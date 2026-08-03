#pragma once

#include <array>
#include <cstdint>

namespace aegis::seal::detail {

using ReleasePepper = std::array<std::uint8_t, 32>;

[[nodiscard]] ReleasePepper release_pepper() noexcept;

}  // namespace aegis::seal::detail
