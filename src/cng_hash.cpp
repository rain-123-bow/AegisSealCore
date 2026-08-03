#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <bcrypt.h>

#include "cng_hash.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

namespace aegis::seal::detail {
namespace {

class AlgorithmHandle final {
public:
    explicit AlgorithmHandle(const wchar_t* algorithm) {
        const auto status = BCryptOpenAlgorithmProvider(
            &handle_, algorithm, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        if (status < 0) {
            throw_status("BCryptOpenAlgorithmProvider", status);
        }
    }

    ~AlgorithmHandle() {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
        }
    }

    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept {
        return handle_;
    }

private:
    [[noreturn]] static void throw_status(const char* operation, const NTSTATUS status) {
        std::ostringstream message;
        message << operation << " failed with NTSTATUS 0x" << std::hex
                << std::setw(8) << std::setfill('0')
                << static_cast<std::uint32_t>(status);
        throw std::runtime_error(message.str());
    }

    BCRYPT_ALG_HANDLE handle_{nullptr};
};

class HashHandle final {
public:
    HashHandle(const BCRYPT_ALG_HANDLE algorithm, const ByteView key) {
        auto* key_data = key.empty()
            ? nullptr
            : const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(key.data()));
        const auto key_size = checked_ulong(key.size(), "HMAC key");
        const auto status = BCryptCreateHash(
            algorithm, &handle_, nullptr, 0, key_data, key_size, 0);
        if (status < 0) {
            throw_status("BCryptCreateHash", status);
        }
    }

    ~HashHandle() {
        if (handle_ != nullptr) {
            BCryptDestroyHash(handle_);
        }
    }

    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;

    void update(const ByteView bytes) const {
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const auto remaining = bytes.size() - offset;
            const auto part_size = static_cast<ULONG>(std::min<std::size_t>(
                remaining, std::numeric_limits<ULONG>::max()));
            auto* part = const_cast<PUCHAR>(
                reinterpret_cast<const UCHAR*>(bytes.data() + offset));
            const auto status = BCryptHashData(handle_, part, part_size, 0);
            if (status < 0) {
                throw_status("BCryptHashData", status);
            }
            offset += part_size;
        }
    }

    template <std::size_t Size>
    [[nodiscard]] std::array<std::uint8_t, Size> finish() const {
        std::array<std::uint8_t, Size> result{};
        const auto status = BCryptFinishHash(
            handle_, result.data(), static_cast<ULONG>(result.size()), 0);
        if (status < 0) {
            throw_status("BCryptFinishHash", status);
        }
        return result;
    }

private:
    [[nodiscard]] static ULONG checked_ulong(
        const std::size_t value,
        const char* description) {
        if (value > std::numeric_limits<ULONG>::max()) {
            throw std::length_error(std::string{description} + " exceeds CNG limit");
        }
        return static_cast<ULONG>(value);
    }

    [[noreturn]] static void throw_status(const char* operation, const NTSTATUS status) {
        std::ostringstream message;
        message << operation << " failed with NTSTATUS 0x" << std::hex
                << std::setw(8) << std::setfill('0')
                << static_cast<std::uint32_t>(status);
        throw std::runtime_error(message.str());
    }

    BCRYPT_HASH_HANDLE handle_{nullptr};
};

template <std::size_t Size>
std::array<std::uint8_t, Size> hmac(
    const wchar_t* algorithm_name,
    const ByteView key,
    const std::initializer_list<ByteView> chunks) {
    const AlgorithmHandle algorithm{algorithm_name};
    const HashHandle hash{algorithm.get(), key};
    for (const auto chunk : chunks) {
        hash.update(chunk);
    }
    return hash.finish<Size>();
}

}  // namespace

Digest256 hmac_sha256(
    const ByteView key,
    const std::initializer_list<ByteView> chunks) {
    return hmac<Digest256{}.size()>(BCRYPT_SHA256_ALGORITHM, key, chunks);
}

Digest512 hmac_sha512(
    const ByteView key,
    const std::initializer_list<ByteView> chunks) {
    return hmac<Digest512{}.size()>(BCRYPT_SHA512_ALGORITHM, key, chunks);
}

}  // namespace aegis::seal::detail
