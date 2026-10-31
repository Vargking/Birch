#pragma once

#include "birch/dex/builder.h"

#include <cstdint>
#include <string>
#include <vector>

namespace birch::guard {

struct FakeClassOptions {
    std::string package_prefix{"Lx/fake/"};
    std::uint32_t class_count{1U};
    std::uint32_t methods_per_class{3U};
    std::uint64_t seed{};
    bool invoke_real_method{false};
    double density{1.0};
    std::vector<dex::MethodBodySpec::MethodReference> real_targets;
    std::uint8_t dex_version{38U};
};

std::vector<std::uint8_t> BuildFakeDex(const FakeClassOptions& options);

} // namespace birch::guard
