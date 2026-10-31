#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace birch::dex {
// Method key -> original instruction boundary -> final code-unit boundary.
// Includes the exclusive code end. Never infer relocation from instruction
// ordinals: conditional relaxation can insert additional instructions.
using CodeAddressMaps = std::map<std::string, std::map<std::uint32_t, std::uint32_t>, std::less<>>;
}
