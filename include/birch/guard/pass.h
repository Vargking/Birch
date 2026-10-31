#pragma once

#include <cstdint>
#include <span>
#include <string_view>

namespace birch::guard {

enum class PassCategory {
    Naming,
    Structure,
    ControlFlow,
    OpaquePredicate,
    Data,
    AntiAnalysis,
    Strength,
};

struct PassDescriptor {
    std::string_view id;
    PassCategory category;
    bool may_increase_code_size;
    bool default_enabled;
    double default_intensity;
};

std::span<const PassDescriptor> PassRegistry();
const PassDescriptor* FindPass(std::string_view id);

} // namespace birch::guard
