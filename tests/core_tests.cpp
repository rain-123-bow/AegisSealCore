#include "aegis_seal/core.hpp"

#include <algorithm>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
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

aegis::seal::Identifier identifier(const std::uint8_t seed) {
    aegis::seal::Identifier result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(seed + index);
    }
    return result;
}

std::string path_with_bytes(const std::initializer_list<std::uint8_t> bytes) {
    std::string path{"src/"};
    for (const auto byte : bytes) {
        path.push_back(static_cast<char>(byte));
    }
    path.append(".cpp");
    return path;
}

void test_logical_order_is_canonical() {
    aegis::seal::Context context{
        .project_id = identifier(0x10),
        .seal_chain_id = identifier(0x40),
        .sequence = 0,
        .previous_seal = {},
    };

    std::vector<aegis::seal::FileEntry> entries{
        {"src/main.cpp", {'i', 'n', 't', ' ', 'm', 'a', 'i', 'n'}},
        {"include/main.hpp", {'#', 'p', 'r', 'a', 'g', 'm', 'a'}},
    };

    const auto first = aegis::seal::compute_seal(context, entries);
    std::reverse(entries.begin(), entries.end());
    const auto second = aegis::seal::compute_seal(context, entries);

    require(first == second, "entry order must not change the logical seal");
    require(
        aegis::seal::format_seal(first).starts_with("ASC1:"),
        "formatted seal must carry the ASC1 version prefix");
}

void test_every_bound_field_changes_the_seal() {
    const aegis::seal::Context genesis{
        .project_id = identifier(0x10),
        .seal_chain_id = identifier(0x40),
        .sequence = 0,
        .previous_seal = {},
    };
    const std::vector<aegis::seal::FileEntry> entries{
        {"include/main.hpp", {'#', 'p', 'r', 'a', 'g', 'm', 'a'}},
        {"src/main.cpp", {'i', 'n', 't', ' ', 'm', 'a', 'i', 'n'}},
    };
    const auto baseline = aegis::seal::compute_seal(genesis, entries);

    auto changed_entries = entries;
    changed_entries[1].content[0] ^= 0x01;
    require(
        baseline != aegis::seal::compute_seal(genesis, changed_entries),
        "one changed content bit must change the seal");

    changed_entries = entries;
    changed_entries[1].path = "src/entry.cpp";
    require(
        baseline != aegis::seal::compute_seal(genesis, changed_entries),
        "a renamed file entry must change the seal");

    auto changed_context = genesis;
    changed_context.project_id[0] ^= 0x01;
    require(
        baseline != aegis::seal::compute_seal(changed_context, entries),
        "project identity must be bound into the seal");

    changed_context = genesis;
    changed_context.seal_chain_id[0] ^= 0x01;
    require(
        baseline != aegis::seal::compute_seal(changed_context, entries),
        "seal-chain identity must be bound into the seal");

    aegis::seal::Context chained = genesis;
    chained.sequence = 1;
    chained.previous_seal = baseline;
    const auto chained_seal = aegis::seal::compute_seal(chained, entries);

    changed_context = chained;
    changed_context.sequence = 2;
    require(
        chained_seal != aegis::seal::compute_seal(changed_context, entries),
        "sequence must be bound into the seal");

    changed_context = chained;
    changed_context.previous_seal[0] ^= 0x01;
    require(
        chained_seal != aegis::seal::compute_seal(changed_context, entries),
        "previous seal must be bound into the next seal");

    require(
        aegis::seal::verify_seal(genesis, entries, baseline),
        "the exact expected seal must verify");
    auto incorrect = baseline;
    incorrect.back() ^= 0x01;
    require(
        !aegis::seal::verify_seal(genesis, entries, incorrect),
        "a one-bit seal mismatch must fail verification");
}

void test_malformed_input_is_rejected() {
    const aegis::seal::Context genesis{
        .project_id = identifier(0x10),
        .seal_chain_id = identifier(0x40),
        .sequence = 0,
        .previous_seal = {},
    };
    require_seal_error(
        [&] { static_cast<void>(aegis::seal::compute_seal(genesis, {})); },
        "an empty file-entry set must be rejected");

    const std::vector<std::string> invalid_paths{
        "",
        "/src/main.cpp",
        "src\\main.cpp",
        "src//main.cpp",
        "src/./main.cpp",
        "src/../main.cpp",
        "src/",
        "include:C/main.hpp",
        path_with_bytes({0x00}),
        path_with_bytes({0xff}),
        path_with_bytes({0x80}),
        path_with_bytes({0xc0, 0xaf}),
        path_with_bytes({0xe2, 0x82}),
        path_with_bytes({0xed, 0xa0, 0x80}),
        path_with_bytes({0xf4, 0x90, 0x80, 0x80}),
    };
    for (const auto& path : invalid_paths) {
        require_seal_error(
            [&] {
                static_cast<void>(aegis::seal::compute_seal(
                    genesis, {{path, {'x'}}}));
            },
            "a malformed path must be rejected");
    }

    require_seal_error(
        [&] {
            static_cast<void>(aegis::seal::compute_seal(
                genesis,
                {{"src/main.cpp", {'a'}}, {"src/main.cpp", {'b'}}}));
        },
        "duplicate logical paths must be rejected");

    auto invalid_context = genesis;
    invalid_context.previous_seal[0] = 1;
    require_seal_error(
        [&] {
            static_cast<void>(aegis::seal::compute_seal(
                invalid_context, {{"src/main.cpp", {'x'}}}));
        },
        "genesis must not claim a previous seal");

    invalid_context = genesis;
    invalid_context.sequence = 1;
    require_seal_error(
        [&] {
            static_cast<void>(aegis::seal::compute_seal(
                invalid_context, {{"src/main.cpp", {'x'}}}));
        },
        "a positive sequence must carry a previous seal");
}

void test_scope_is_defined_by_the_caller() {
    const aegis::seal::Context context{
        .project_id = identifier(0x10),
        .seal_chain_id = identifier(0x40),
        .sequence = 0,
        .previous_seal = {},
    };
    const std::vector<aegis::seal::FileEntry> entries{
        {"CMakeLists.txt", {'c', 'm', 'a', 'k', 'e'}},
        {"config/runtime.json", {'{', '}'}},
        {"plugins/production.json", {'[', ']'}},
    };

    try {
        const auto seal = aegis::seal::compute_seal(context, entries);
        require(
            aegis::seal::verify_seal(context, entries, seal),
            "the core must accept normalized runtime-scope paths selected by the caller");
    } catch (const aegis::seal::SealError&) {
        require(
            false,
            "the core must accept normalized runtime-scope paths selected by the caller");
    }
}

void test_valid_multibyte_utf8_paths_are_canonical() {
    const aegis::seal::Context context{
        .project_id = identifier(0x30),
        .seal_chain_id = identifier(0x70),
        .sequence = 0,
        .previous_seal = {},
    };
    std::vector<aegis::seal::FileEntry> entries{
        {path_with_bytes({0xc3, 0xa9}), {'u', 't', 'f', '8'}},
        {"src/a.cpp", {'a', 's', 'c', 'i', 'i'}},
    };

    const auto first = aegis::seal::compute_seal(context, entries);
    std::reverse(entries.begin(), entries.end());
    const auto second = aegis::seal::compute_seal(context, entries);
    require(
        first == second,
        "valid multibyte UTF-8 paths must retain unsigned-byte canonical ordering");
    require(
        aegis::seal::format_seal(first) ==
            "ASC1:f1d651ef33bdd93fe45e96349bfc81df5dea64ec6f497ea75bda19e037c5cb42",
        "the independent UTF-8 vector must lock unsigned-byte path ordering");
}

void test_seal_text_is_strict_and_round_trips() {
    const aegis::seal::Context context{
        .project_id = identifier(0x10),
        .seal_chain_id = identifier(0x40),
        .sequence = 0,
        .previous_seal = {},
    };
    const std::vector<aegis::seal::FileEntry> entries{
        {"src/main.cpp", {'x'}},
    };
    const auto seal = aegis::seal::compute_seal(context, entries);
    const auto text = aegis::seal::format_seal(seal);
    require(
        aegis::seal::parse_seal(text) == seal,
        "canonical seal text must round-trip without loss");

    require_seal_error(
        [&] { static_cast<void>(aegis::seal::parse_seal(text.substr(1))); },
        "a seal with an invalid prefix or length must be rejected");
    auto uppercase = text;
    uppercase[5] = 'A';
    require_seal_error(
        [&] { static_cast<void>(aegis::seal::parse_seal(uppercase)); },
        "uppercase hexadecimal must be rejected as non-canonical");
}

void test_fixed_vector_locks_zero_based_file_ordinal() {
    const aegis::seal::Context context{
        .project_id = identifier(0x10),
        .seal_chain_id = identifier(0x40),
        .sequence = 0,
        .previous_seal = {},
    };
    const std::vector<aegis::seal::FileEntry> entries{
        {"src/main.cpp", {'i', 'n', 't', ' ', 'm', 'a', 'i', 'n'}},
        {"include/main.hpp", {'#', 'p', 'r', 'a', 'g', 'm', 'a'}},
    };
    const auto text = aegis::seal::format_seal(
        aegis::seal::compute_seal(context, entries));

    require(
        text == "ASC1:0cb65a29352e00e8370541f18b04c4f88d881eb93e193a0be9cdcf40763cf00e",
        "ASC-1 must match the independent vector with first file ordinal zero");
    require(
        text.substr(5) != "1b5a820aa8ac5dd04d301040ffc825fff737e0282dc3d8b674b2cc142092ed47",
        "ASC-1 must not alias raw SHA-256 of the canonical entries");
    require(
        text.substr(5) != "ad92f32ecb76e6777bcc160adfa7df4341d44045973cfd3ea1884c060f771cf6",
        "ASC-1 must not alias truncated SHA-512 of the canonical entries");
}

void test_large_content_is_deterministic_and_fully_bound() {
    const aegis::seal::Context context{
        .project_id = identifier(0x20),
        .seal_chain_id = identifier(0x60),
        .sequence = 0,
        .previous_seal = {},
    };
    std::vector<std::uint8_t> content(1024U * 1024U);
    for (std::size_t index = 0; index < content.size(); ++index) {
        content[index] = static_cast<std::uint8_t>((index * 131U + 17U) & 0xffU);
    }
    std::vector<aegis::seal::FileEntry> entries{
        {"src/large.bin", std::move(content)},
    };

    const auto first = aegis::seal::compute_seal(context, entries);
    const auto second = aegis::seal::compute_seal(context, entries);
    require(first == second, "a one-megabyte input must produce a stable seal");

    entries.front().content.back() ^= 0x01;
    require(
        first != aegis::seal::compute_seal(context, entries),
        "the final bit of a one-megabyte input must affect the seal");
}

}  // namespace

int main() {
    test_scope_is_defined_by_the_caller();
    test_logical_order_is_canonical();
    test_every_bound_field_changes_the_seal();
    test_malformed_input_is_rejected();
    test_valid_multibyte_utf8_paths_are_canonical();
    test_seal_text_is_strict_and_round_trips();
    test_fixed_vector_locks_zero_based_file_ordinal();
    test_large_content_is_deterministic_and_fully_bound();
    std::cout << "PASS: ASC-1 core tests\n";
    return 0;
}
