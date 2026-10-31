#pragma once

#include "birch/dex/code.h"

#include <cstdint>
#include <span>

namespace birch::test {

// Deliberately narrow independent oracle, not an ART replacement. Unsupported
// instructions, invalid jumps and nontermination fail instead of being skipped.
class IntDexInterpreter final {
public:
    static std::uint32_t Execute(const dex::CodeItem& code,
                                 std::span<const std::uint32_t> arguments);
};

} // namespace birch::test
