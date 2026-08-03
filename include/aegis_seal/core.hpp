#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace aegis::seal {

using Identifier = std::array<std::uint8_t, 16>;
using Seal = std::array<std::uint8_t, 32>;

struct Context {
    Identifier project_id{};
    Identifier run_id{};
    std::uint64_t sequence{};
    Seal previous_seal{};
};

struct FileEntry {
    std::string path;
    std::vector<std::uint8_t> content;
};

class SealError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] Seal compute_seal(const Context& context, const std::vector<FileEntry>& entries);
[[nodiscard]] bool verify_seal(
    const Context& context,
    const std::vector<FileEntry>& entries,
    const Seal& expected);
[[nodiscard]] std::string format_seal(const Seal& seal);
[[nodiscard]] Seal parse_seal(std::string_view text);

}  // namespace aegis::seal
