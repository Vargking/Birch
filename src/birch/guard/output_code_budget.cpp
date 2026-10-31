#include "output_code_budget.h"

#include "strength_policy.h"
#include "birch/guard/scope.h"

#include <cstdint>
#include <stdexcept>

namespace birch::guard::detail {
namespace {
std::uint32_t CodeUnits(const dex::DexFile& file, std::size_t code_offset) {
    const auto bytes = file.bytes();
    constexpr std::size_t header_size = 16U;
    if (code_offset > bytes.size() || bytes.size() - code_offset < header_size)
        throw std::runtime_error("truncated final code_item header");
    std::uint32_t units{};
    for (unsigned i = 0U; i < 4U; ++i)
        units |= static_cast<std::uint32_t>(bytes[code_offset + 12U + i]) << (8U * i);
    if (units > (bytes.size() - code_offset - header_size) / 2U)
        throw std::runtime_error("truncated final code_item instructions");
    return units;
}
} // namespace

void OutputCodeBudget::Verify(const dex::DexFile& file, const GuardConfig& config,
                             const ClassMap& class_renames) {
    ClassMap original_owners;
    for (const auto& [original, renamed] : class_renames) {
        const auto [at, inserted] = original_owners.emplace(renamed, original);
        if (!inserted && at->second != original)
            throw std::invalid_argument("ambiguous final code-budget class rename");
    }
    const ScopeMatcher scope(config.scope);
    const auto limit = StrengthPolicy::CodeUnitLimit(config);
    for (std::size_t c = 0U; c < file.classes().size(); ++c) {
        const auto owner = file.descriptor(file.classes()[c].class_idx);
        const auto renamed = original_owners.find(owner);
        const auto& original = renamed == original_owners.end() ? owner : renamed->second;
        if (!scope.IsProtected(original) || !scope.AllowsCodeTransforms(original)) continue;
        const auto& data = file.class_data(c);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (!method.code_off) continue;
                const auto units = CodeUnits(file, method.code_off);
                if (units > limit)
                    throw std::length_error("final serialized code-unit limit violated for " +
                        file.method_key(method.method_idx) + ": " + std::to_string(units) +
                        " code units, maximum " + std::to_string(limit));
            }
        }
    }
}

} // namespace birch::guard::detail
