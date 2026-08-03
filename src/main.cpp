#include "aegis_seal/core.hpp"
#include "manifest.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

namespace {

constexpr int kSuccess = 0;
constexpr int kMismatch = 2;
constexpr int kInvalidInput = 3;

void print_usage() {
    std::wcerr
        << L"Usage:\n"
        << L"  aegis-seal compute <manifest>\n"
        << L"  aegis-seal verify <manifest> <ASC1:seal>\n";
}

std::string ascii(const std::wstring_view value) {
    std::string output;
    output.reserve(value.size());
    for (const auto character : value) {
        if (character < 0 || character > 0x7f) {
            throw aegis::seal::SealError{"ASC-1 seal text must be ASCII"};
        }
        output.push_back(static_cast<char>(character));
    }
    return output;
}

aegis::seal::detail::Manifest load_manifest(const wchar_t* path) {
    std::ifstream input{std::filesystem::path{path}, std::ios::binary};
    if (!input) {
        throw aegis::seal::SealError{"ASC-1 manifest cannot be opened"};
    }
    return aegis::seal::detail::read_manifest(input);
}

int run(const int argument_count, wchar_t* arguments[]) {
    if (argument_count < 2) {
        print_usage();
        return kInvalidInput;
    }

    const std::wstring_view operation{arguments[1]};
    if (operation == L"compute") {
        if (argument_count != 3) {
            print_usage();
            return kInvalidInput;
        }
        const auto manifest = load_manifest(arguments[2]);
        const auto seal = aegis::seal::compute_seal(
            manifest.context, manifest.entries);
        std::cout << aegis::seal::format_seal(seal) << '\n';
        return kSuccess;
    }

    if (operation == L"verify") {
        if (argument_count != 4) {
            print_usage();
            return kInvalidInput;
        }
        const auto manifest = load_manifest(arguments[2]);
        const auto expected = aegis::seal::parse_seal(ascii(arguments[3]));
        if (aegis::seal::verify_seal(
                manifest.context, manifest.entries, expected)) {
            std::cout << "MATCH\n";
            return kSuccess;
        }
        std::cout << "MISMATCH\n";
        return kMismatch;
    }

    print_usage();
    return kInvalidInput;
}

}  // namespace

int wmain(const int argument_count, wchar_t* arguments[]) {
    try {
        return run(argument_count, arguments);
    } catch (const aegis::seal::SealError& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
        return kInvalidInput;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: unexpected failure: " << error.what() << '\n';
        return kInvalidInput;
    }
}
