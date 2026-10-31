#pragma once

#include "birch/utils/hash.h"

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace birch::guard {

inline constexpr std::size_t kRuntimeConstantStateFields = 2U;

[[nodiscard]] inline std::string RuntimeConstantMethodName(std::uint64_t seed) {
    std::ostringstream stream;
    stream << 'c' << std::hex << std::setfill('0') << std::setw(16)
           << utils::StableHash64("constant-runtime-method", seed);
    return stream.str();
}

[[nodiscard]] inline std::string RuntimeFloatConstantMethodName(
    std::uint64_t seed) {
    std::ostringstream stream;
    stream << 'f' << std::hex << std::setfill('0') << std::setw(16)
           << utils::StableHash64("constant-runtime-float-method", seed);
    return stream.str();
}

[[nodiscard]] inline std::string RuntimeNullConstantMethodName(
    std::uint64_t seed) {
    std::ostringstream stream;
    stream << 'n' << std::hex << std::setfill('0') << std::setw(16)
           << utils::StableHash64("constant-runtime-null-method", seed);
    return stream.str();
}

[[nodiscard]] inline std::string RuntimeConstantFieldName(
    std::uint64_t seed, std::size_t slot) {
    std::ostringstream stream;
    stream << 'f' << std::hex << std::setfill('0') << std::setw(16)
           << utils::StableHash64(
                  "constant-runtime-field:" + std::to_string(slot), seed);
    return stream.str();
}

[[nodiscard]] inline std::string RuntimeNullConstantFieldName(
    std::uint64_t seed) {
    std::ostringstream stream;
    stream << 'o' << std::hex << std::setfill('0') << std::setw(16)
           << utils::StableHash64("constant-runtime-null-field", seed);
    return stream.str();
}

} // namespace birch::guard
