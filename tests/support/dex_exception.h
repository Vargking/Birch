#pragma once

#include <cstdint>
#include <string_view>

namespace birch::test {

// Deliberately not std::exception: oracle failures (unsupported opcodes,
// undefined registers, bounds and execution budgets) are never DEX catches.
struct DexThrown {
    std::uint32_t object;
};

inline bool MatchesException(std::string_view caught, std::string_view type) {
    return caught == type || caught == "Ljava/lang/Throwable;" ||
        (type == "Ljava/lang/NullPointerException;" &&
         (caught == "Ljava/lang/RuntimeException;" || caught == "Ljava/lang/Exception;"));
}

} // namespace birch::test
