#include "cff_type_domains.h"
#include "birch/dex/liveness.h"

#include <algorithm>
#include <map>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>

namespace birch::guard::detail {

CffTypeDomains::CffTypeDomains(const dex::DexFile& file,
    const dex::DexEncodedMethod& method, const dex::MethodIr& ir,
    std::span<const std::uint16_t> redefined_scratch, bool share, bool project_live)
    : owners_(ir.blocks().size()), counts_(ir.blocks().size()) {
    // Register equality does not prove monitor-stack equality. Until lock
    // identities are part of the analysis, do not merge explicit-monitor
    // methods (including a synchronized block with an exceptional unlock).
    const bool has_explicit_monitor = std::any_of(ir.code().instructions.begin(),
        ir.code().instructions.end(), [](const auto& instruction) {
            return instruction.opcode == 0x1dU || instruction.opcode == 0x1eU;
        });
    if (!share || has_explicit_monitor) {
        std::iota(owners_.begin(), owners_.end(), 0U);
        std::fill(counts_.begin(), counts_.end(), 1U);
        return;
    }
    std::vector<std::uint32_t> exits;
    const dex::MethodLiveness liveness(ir);
    std::map<std::uint32_t, std::vector<std::uint16_t>> live_exits;
    exits.reserve(ir.blocks().size());
    for (const auto& block : ir.blocks()) {
        exits.push_back(block.instructions.back().dex_offset);
        live_exits.emplace(exits.back(), liveness.LiveOut(block.id));
    }
    const auto types = dex::AnalyzeMethodTypes(file, method, ir.code(),
        {exits, redefined_scratch, project_live ? &live_exits : nullptr, project_live});
    if (!types.issues.empty()) {
        throw std::runtime_error("cannot share invalid verifier domains in " +
                                 file.method_key(method.method_idx));
    }
    if (project_live) {
        struct Group {
            dex::BlockId owner;
            std::vector<bool> live;
            // A value is present only if ALL members agree, including members
            // where that word is currently dead. A later member may need it.
            std::vector<std::optional<std::string>> common;
        };
        std::vector<dex::BlockId> previous;
        bool first_pass = true;
        do {
          previous = owners_;
          const dex::MethodLiveness expanded(ir, first_pass ?
              std::span<const dex::BlockId>{} : std::span<const dex::BlockId>{previous});
          first_pass = false;
          std::fill(counts_.begin(), counts_.end(), 0U);
          std::vector<Group> groups;
          for (const auto& block : ir.blocks()) {
            const auto& registers = types.exit_register_domains.at(block.instructions.back().dex_offset);
            std::vector<bool> live(registers.size());
            for (auto reg : expanded.LiveOut(block.id)) live.at(reg) = true;
            for (auto reg : redefined_scratch) if (reg < live.size()) live[reg] = false;
            auto group = std::find_if(groups.begin(), groups.end(), [&](const Group& candidate) {
                if (previous[candidate.owner] != previous[block.id]) return false;
                for (std::size_t r = 0; r < live.size(); ++r)
                    if ((live[r] || candidate.live[r]) &&
                        (!candidate.common[r] || *candidate.common[r] != registers[r])) return false;
                return true;
            });
            if (group == groups.end()) {
                Group added{block.id, live, {}};
                for (const auto& reg : registers) added.common.emplace_back(reg);
                groups.push_back(std::move(added));
                owners_[block.id] = block.id;
                counts_[block.id] = 1U;
            } else {
                owners_[block.id] = group->owner;
                ++counts_[group->owner];
                for (std::size_t r = 0; r < live.size(); ++r) {
                    group->live[r] = group->live[r] || live[r];
                    if (group->common[r] && *group->common[r] != registers[r]) group->common[r].reset();
                }
            }
          }
        } while (previous != owners_);
        return;
    }
    std::map<std::string, dex::BlockId, std::less<>> first;
    for (const auto& block : ir.blocks()) {
        const auto& signature = types.exit_type_domains.at(
            block.instructions.back().dex_offset);
        const auto owner = first.emplace(signature, block.id).first->second;
        owners_.at(block.id) = owner;
        ++counts_.at(owner);
    }
}

} // namespace birch::guard::detail
