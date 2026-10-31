#include "birch/dex/checksum.h"

#include <algorithm>

namespace birch::dex {
namespace {

void WriteU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

std::uint32_t RotateLeft(std::uint32_t value, unsigned count) {
    return (value << count) | (value >> (32U - count));
}

} // namespace

std::array<std::uint8_t, 20> Sha1(std::span<const std::uint8_t> bytes) {
    std::uint64_t bit_length = static_cast<std::uint64_t>(bytes.size()) * 8U;
    std::vector<std::uint8_t> message(bytes.begin(), bytes.end());
    message.push_back(0x80U);
    while ((message.size() % 64U) != 56U) message.push_back(0U);
    for (int shift = 56; shift >= 0; shift -= 8) {
        message.push_back(static_cast<std::uint8_t>(bit_length >> shift));
    }
    std::uint32_t h0 = 0x67452301U;
    std::uint32_t h1 = 0xefcdab89U;
    std::uint32_t h2 = 0x98badcfeU;
    std::uint32_t h3 = 0x10325476U;
    std::uint32_t h4 = 0xc3d2e1f0U;
    for (std::size_t chunk = 0; chunk < message.size(); chunk += 64U) {
        std::array<std::uint32_t, 80> words{};
        for (std::size_t i = 0; i < 16U; ++i) {
            const auto offset = chunk + i * 4U;
            words[i] = static_cast<std::uint32_t>(message[offset]) << 24U |
                       static_cast<std::uint32_t>(message[offset + 1U]) << 16U |
                       static_cast<std::uint32_t>(message[offset + 2U]) << 8U |
                       static_cast<std::uint32_t>(message[offset + 3U]);
        }
        for (std::size_t i = 16U; i < 80U; ++i) {
            words[i] = RotateLeft(words[i - 3U] ^ words[i - 8U] ^ words[i - 14U] ^ words[i - 16U], 1U);
        }
        auto a = h0; auto b = h1; auto c = h2; auto d = h3; auto e = h4;
        for (std::size_t i = 0; i < 80U; ++i) {
            std::uint32_t function = 0; std::uint32_t constant = 0;
            if (i < 20U) { function = (b & c) | ((~b) & d); constant = 0x5a827999U; }
            else if (i < 40U) { function = b ^ c ^ d; constant = 0x6ed9eba1U; }
            else if (i < 60U) { function = (b & c) | (b & d) | (c & d); constant = 0x8f1bbcdcU; }
            else { function = b ^ c ^ d; constant = 0xca62c1d6U; }
            const auto next = RotateLeft(a, 5U) + function + e + constant + words[i];
            e = d; d = c; c = RotateLeft(b, 30U); b = a; a = next;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    std::array<std::uint8_t, 20> result{};
    const std::array<std::uint32_t, 5> words{h0, h1, h2, h3, h4};
    for (std::size_t i = 0; i < words.size(); ++i) {
        result[i * 4U] = static_cast<std::uint8_t>(words[i] >> 24U);
        result[i * 4U + 1U] = static_cast<std::uint8_t>(words[i] >> 16U);
        result[i * 4U + 2U] = static_cast<std::uint8_t>(words[i] >> 8U);
        result[i * 4U + 3U] = static_cast<std::uint8_t>(words[i]);
    }
    return result;
}

std::uint32_t Adler32(std::span<const std::uint8_t> bytes) {
    constexpr std::uint32_t kMod = 65521U;
    std::uint32_t a = 1U;
    std::uint32_t b = 0U;
    for (const auto value : bytes) {
        a = (a + value) % kMod;
        b = (b + a) % kMod;
    }
    return b << 16U | a;
}

void UpdateDexChecksums(std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 0x70U) return;
    const auto signature = Sha1(std::span<const std::uint8_t>(bytes.data() + 0x20U,
                                                               bytes.size() - 0x20U));
    std::copy(signature.begin(), signature.end(), bytes.begin() + 0x0cU);
    const auto checksum = Adler32(std::span<const std::uint8_t>(bytes.data() + 0x0cU,
                                                                  bytes.size() - 0x0cU));
    WriteU32(bytes, 0x08U, checksum);
}

} // namespace birch::dex
