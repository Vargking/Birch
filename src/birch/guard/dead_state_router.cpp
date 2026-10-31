#include "dead_state_router.h"

#include <algorithm>
#include <stdexcept>

namespace birch::guard::detail {

DeadStateRouter::DeadStateRouter(CffAssembler& assembler, std::uint16_t state_register,
                                 std::span<const std::uint32_t> states,
                                 std::span<const CffAssembler::Label> targets,
                                 bool packed, std::uint64_t seed)
    : assembler_(&assembler), state_register_(state_register), packed_(packed),
      local_decoders_(packed),
      states_(states.begin(), states.end()) {
    if (states.size() != targets.size()) throw std::invalid_argument("dead shard size mismatch");
    if (states.empty()) return;
    first_ = states.front();
    // At most 32 independently keyed switches; normally 128 states per switch.
    // Local decode islands keep short edges compact without restoring a
    // method-wide decode hub or duplicating switch tables at every island.
    while (((states.size() - 1U) >> shift_) >= 32U) ++shift_;
    std::size_t count = packed ? ((states.size() - 1U) >> shift_) + 1U : 1U;
    if (!packed)
        while (count < 32U && count * 128U < states.size()) count *= 2U;
    shards_.reserve(count);
    edges_.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto dispatcher = assembler.NewLabel();
        shards_.push_back({dispatcher, {}, {}});
        // Odd keys differ between shards even for consecutive/repeated seeds.
        edges_.emplace_back(assembler, state_register, dispatcher,
                            seed + i * 0x9e3779b97f4a7c16ULL, local_decoders_);
    }
    for (std::size_t i = 0; i < states.size(); ++i) {
        if (packed && states[i] != first_ + static_cast<std::uint32_t>(i))
            throw std::invalid_argument("nonconsecutive packed dead states");
        const auto shard = packed ? i >> shift_ : states[i] & (count - 1U);
        shard_by_state_.push_back(shard);
        shards_[shard].keys.push_back(states[i]);
        shards_[shard].targets.push_back(targets[i]);
    }
}

void DeadStateRouter::EmitSelector(std::uint16_t scratch_register) {
    if (shards_.empty() || scratch_register > 255U || scratch_register == state_register_)
        throw std::invalid_argument("invalid dead shard selector register");
    if (packed_) {
        assembler_->EmitConst32(scratch_register, first_);
        assembler_->Emit({static_cast<std::uint16_t>(0x91U | (scratch_register << 8U)),
                          static_cast<std::uint16_t>(state_register_ | (scratch_register << 8U))});
        assembler_->Emit({static_cast<std::uint16_t>(0xe2U | (scratch_register << 8U)),
                          static_cast<std::uint16_t>(scratch_register | (shift_ << 8U))});
    } else {
        assembler_->Emit({static_cast<std::uint16_t>(0xddU | (scratch_register << 8U)),
                          static_cast<std::uint16_t>(state_register_ | ((shards_.size() - 1U) << 8U))});
    }
}

void DeadStateRouter::EmitEdge(std::uint32_t current, std::size_t target, std::uint64_t salt) {
    edges_.at(shard_by_state_.at(target)).Emit(current, states_.at(target), salt);
}

void DeadStateRouter::EmitFallback(std::size_t shard, std::uint64_t salt) {
    const auto& table = shards_.at(shard);
    if (table.keys.empty()) throw std::invalid_argument("empty dead fallback shard");
    const auto index = static_cast<std::size_t>(salt % table.keys.size());
    // Invalid input has no known current token. Normalize it explicitly rather
    // than feeding an arbitrary value into a relative edge or a shared trap.
    assembler_->EmitEncodedState(state_register_, table.keys[index], salt);
    assembler_->EmitGoto16(table.targets[index]);
}

void DeadStateRouter::EmitEntry(std::size_t target) {
    edges_.at(shard_by_state_.at(target)).EmitEntry(states_.at(target));
}

void DeadStateRouter::FlushLocalDecoders() {
    if (local_decoders_)
        for (auto& edge : edges_) edge.BindDecoder();
}

void DeadStateRouter::BindShard(std::size_t shard) {
    // Encoded edges enter the decoder; root/fallback edges enter immediately
    // after it. The decoder falls through, with no extra common-hub jump.
    edges_.at(shard).BindDecoder(true);
    assembler_->Bind(shards_.at(shard).dispatcher);
}

} // namespace birch::guard::detail
