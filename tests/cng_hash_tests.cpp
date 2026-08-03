#include "cng_hash.hpp"

#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace {

template <std::size_t Size>
std::string to_hex(const std::array<std::uint8_t, Size>& bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

void require_equal(
    const std::string_view actual,
    const std::string_view expected,
    const std::string_view message) {
    if (actual != expected) {
        std::cerr << "FAIL: " << message << "\nactual:   " << actual
                  << "\nexpected: " << expected << '\n';
        std::exit(1);
    }
}

void test_rfc4231_case_one() {
    const std::array<std::uint8_t, 20> key{
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    constexpr std::string_view data = "Hi There";
    const auto bytes = std::as_bytes(std::span{data});
    const auto input = aegis::seal::detail::ByteView{
        reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};

    require_equal(
        to_hex(aegis::seal::detail::hmac_sha256(key, {input})),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "HMAC-SHA256 must match RFC 4231 test case 1");
    require_equal(
        to_hex(aegis::seal::detail::hmac_sha512(key, {input})),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        "HMAC-SHA512 must match RFC 4231 test case 1");
}

}  // namespace

int main() {
    test_rfc4231_case_one();
    std::cout << "PASS: Windows CNG HMAC tests\n";
    return 0;
}
