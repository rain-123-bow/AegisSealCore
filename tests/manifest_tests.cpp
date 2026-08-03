#include "manifest.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

void require(const bool condition, const std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

template <typename Operation>
void require_seal_error(Operation&& operation, const std::string_view message) {
    try {
        operation();
    } catch (const aegis::seal::SealError&) {
        return;
    }
    std::cerr << "FAIL: " << message << '\n';
    std::exit(1);
}

template <std::size_t Size>
void append(std::vector<std::uint8_t>& output, const std::array<std::uint8_t, Size>& value) {
    output.insert(output.end(), value.begin(), value.end());
}

void append(std::vector<std::uint8_t>& output, const std::string_view value) {
    output.insert(output.end(), value.begin(), value.end());
}

template <typename Integer>
void append_little_endian(std::vector<std::uint8_t>& output, const Integer value) {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
        output.push_back(static_cast<std::uint8_t>(value >> (index * 8U)));
    }
}

template <typename Integer>
void set_little_endian(
    std::vector<std::uint8_t>& output,
    const std::size_t offset,
    const Integer value) {
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
        output.at(offset + index) =
            static_cast<std::uint8_t>(value >> (index * 8U));
    }
}

struct EntryBytes {
    std::string_view path;
    std::string_view content;
};

std::vector<std::uint8_t> manifest_bytes(
    const std::initializer_list<EntryBytes> entries) {
    std::vector<std::uint8_t> output;
    append(output, "ASC1MF\r\n");
    for (std::uint8_t value = 0x10; value < 0x20; ++value) {
        output.push_back(value);
    }
    for (std::uint8_t value = 0x40; value < 0x50; ++value) {
        output.push_back(value);
    }
    append_little_endian<std::uint64_t>(output, 0);
    output.insert(output.end(), 32, 0);
    append_little_endian<std::uint32_t>(
        output, static_cast<std::uint32_t>(entries.size()));
    for (const auto& entry : entries) {
        append_little_endian<std::uint32_t>(
            output, static_cast<std::uint32_t>(entry.path.size()));
        append(output, entry.path);
        append_little_endian<std::uint64_t>(output, entry.content.size());
        append(output, entry.content);
    }
    return output;
}

std::vector<std::uint8_t> valid_manifest_bytes() {
    return manifest_bytes({{"src/main.cpp", "int main"}});
}

aegis::seal::detail::Manifest parse(const std::vector<std::uint8_t>& bytes) {
    const std::string storage{
        reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    std::istringstream input{storage, std::ios::binary};
    return aegis::seal::detail::read_manifest(input);
}

void test_valid_manifest_is_decoded() {
    const auto manifest = parse(valid_manifest_bytes());
    require(manifest.context.project_id.front() == 0x10, "project ID must be decoded");
    require(manifest.context.run_id.back() == 0x4f, "run ID must be decoded");
    require(manifest.context.sequence == 0, "sequence must be decoded");
    require(manifest.entries.size() == 1, "file count must be decoded");
    require(manifest.entries[0].path == "src/main.cpp", "path must be decoded");
    require(manifest.entries[0].content.size() == 8, "content must be decoded");
}

void test_truncation_and_trailing_bytes_are_rejected() {
    auto truncated = valid_manifest_bytes();
    truncated.pop_back();
    require_seal_error(
        [&] { static_cast<void>(parse(truncated)); },
        "a truncated manifest must be rejected");

    auto trailing = valid_manifest_bytes();
    trailing.push_back(0xff);
    require_seal_error(
        [&] { static_cast<void>(parse(trailing)); },
        "trailing bytes must be rejected");
}

void test_declared_v1_limits_are_rejected_before_allocation() {
    constexpr std::size_t file_count_offset = 80;
    constexpr std::size_t path_length_offset = 84;
    constexpr std::size_t content_length_offset = 100;

    auto invalid_magic = valid_manifest_bytes();
    invalid_magic.front() ^= 0x01;
    require_seal_error(
        [&] { static_cast<void>(parse(invalid_magic)); },
        "an invalid manifest magic must be rejected");

    for (const auto count : {std::uint32_t{0}, std::uint32_t{100'001}}) {
        auto invalid_count = valid_manifest_bytes();
        set_little_endian(invalid_count, file_count_offset, count);
        require_seal_error(
            [&] { static_cast<void>(parse(invalid_count)); },
            "an out-of-range file count must be rejected");
    }

    for (const auto length : {std::uint32_t{0}, std::uint32_t{32'769}}) {
        auto invalid_path_length = valid_manifest_bytes();
        set_little_endian(invalid_path_length, path_length_offset, length);
        require_seal_error(
            [&] { static_cast<void>(parse(invalid_path_length)); },
            "an out-of-range path length must be rejected");
    }

    auto oversized_content = valid_manifest_bytes();
    set_little_endian(
        oversized_content,
        content_length_offset,
        std::uint64_t{256} * 1024U * 1024U + 1U);
    require_seal_error(
        [&] { static_cast<void>(parse(oversized_content)); },
        "an oversized content declaration must be rejected before allocation");
}

class FailingAtEofBuffer final : public std::streambuf {
public:
    explicit FailingAtEofBuffer(const std::vector<std::uint8_t>& bytes)
        : storage_(reinterpret_cast<const char*>(bytes.data()), bytes.size()) {}

protected:
    std::streamsize xsgetn(char* destination, const std::streamsize count) override {
        if (count <= 0) {
            return 0;
        }
        const auto requested = static_cast<std::size_t>(count);
        const auto available = storage_.size() - position_;
        const auto copied = std::min(requested, available);
        std::memcpy(destination, storage_.data() + position_, copied);
        position_ += copied;
        return static_cast<std::streamsize>(copied);
    }

    int_type underflow() override {
        if (position_ < storage_.size()) {
            return traits_type::to_int_type(storage_[position_]);
        }
        throw std::runtime_error{"forced tail-read failure"};
    }

private:
    std::string storage_;
    std::size_t position_{};
};

void test_tail_io_failure_is_rejected() {
    FailingAtEofBuffer buffer{valid_manifest_bytes()};
    std::istream input{&buffer};
    require_seal_error(
        [&] { static_cast<void>(aegis::seal::detail::read_manifest(input)); },
        "a tail probe I/O failure must not be accepted as clean EOF");
}

void test_total_content_limit_is_exercised_without_large_allocation() {
    require(
        aegis::seal::detail::kV1ManifestLimits.max_file_count == 100'000 &&
            aegis::seal::detail::kV1ManifestLimits.max_path_bytes == 32'768 &&
            aegis::seal::detail::kV1ManifestLimits.max_content_bytes ==
                256ULL * 1024ULL * 1024ULL &&
            aegis::seal::detail::kV1ManifestLimits.max_total_content_bytes ==
                1024ULL * 1024ULL * 1024ULL,
        "the compiled v1 parser limits must match the normative contract");

    const auto bytes = manifest_bytes({
        {"src/a.cpp", "abcd"},
        {"src/b.cpp", "efg"},
    });
    const std::string storage{
        reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    std::istringstream input{storage, std::ios::binary};
    const aegis::seal::detail::ManifestLimits limits{
        .max_file_count = 2,
        .max_path_bytes = 32,
        .max_content_bytes = 4,
        .max_total_content_bytes = 6,
    };
    require_seal_error(
        [&] {
            static_cast<void>(aegis::seal::detail::read_manifest(input, limits));
        },
        "the cumulative content limit must reject the crossing entry");
}

}  // namespace

int main() {
    test_valid_manifest_is_decoded();
    test_truncation_and_trailing_bytes_are_rejected();
    test_declared_v1_limits_are_rejected_before_allocation();
    test_tail_io_failure_is_rejected();
    test_total_content_limit_is_exercised_without_large_allocation();
    std::cout << "PASS: ASC-1 manifest tests\n";
    return 0;
}
