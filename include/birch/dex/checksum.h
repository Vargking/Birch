#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace birch::dex {

std::array<std::uint8_t, 20> Sha1(std::span<const std::uint8_t> bytes);
std::uint32_t Adler32(std::span<const std::uint8_t> bytes);
void UpdateDexChecksums(std::vector<std::uint8_t>& bytes);

} // namespace birch::dex
