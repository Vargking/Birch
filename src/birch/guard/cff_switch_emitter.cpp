#include "cff_switch_emitter.h"

#include <algorithm>
#include <bit>
#include <limits>
#include <numeric>
#include <stdexcept>

namespace birch::guard::detail {
namespace {
std::uint32_t Displacement(std::size_t target, std::size_t source) {
    const auto delta = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(source);
    if (delta < std::numeric_limits<std::int32_t>::min() ||
        delta > std::numeric_limits<std::int32_t>::max())
        throw std::length_error("CFF switch displacement exceeds int32");
    return static_cast<std::uint32_t>(static_cast<std::int32_t>(delta));
}
} // namespace

CffSwitchEmitter::CffSwitchEmitter(CffAssembler& assembler, CffAssembler::Label invalid_target)
    : assembler_(&assembler), invalid_target_(invalid_target) {}

void CffSwitchEmitter::Emit(std::uint16_t reg, std::vector<std::uint32_t> keys,
                            std::vector<CffAssembler::Label> targets, bool prefer_packed,
                            std::optional<CffAssembler::Label> invalid_target, bool inline_default) {
    if (payloads_emitted_ || reg > 255U || keys.empty() || keys.size() != targets.size() ||
        keys.size() > 0xffffU)
        throw std::invalid_argument("invalid CFF dispatcher payload");
    std::vector<std::size_t> order(keys.size());
    std::iota(order.begin(), order.end(), 0U);
    std::sort(order.begin(), order.end(), [&](auto left, auto right) {
        return std::bit_cast<std::int32_t>(keys[left]) < std::bit_cast<std::int32_t>(keys[right]);
    });
    std::vector<std::uint32_t> sorted_keys;
    std::vector<CffAssembler::Label> sorted_targets;
    bool packed = prefer_packed;
    for (const auto index : order) {
        if (!sorted_keys.empty()) {
            if (keys[index] == sorted_keys.back())
                throw std::invalid_argument("duplicate CFF dispatcher key");
            if (static_cast<std::int64_t>(std::bit_cast<std::int32_t>(sorted_keys.back())) + 1 !=
                std::bit_cast<std::int32_t>(keys[index])) packed = false;
        }
        sorted_keys.push_back(keys[index]);
        sorted_targets.push_back(targets[index]);
    }
    // An unsigned state sequence can straddle INT32_MAX. DEX packed keys may
    // not wrap signed order; retain all cases using a sparse payload instead.
    const auto at = assembler_->position();
    assembler_->Emit({static_cast<std::uint16_t>((packed ? 0x2bU : 0x2cU) | (reg << 8U)), 0U, 0U});
    if (!inline_default) assembler_->EmitGoto32(invalid_target.value_or(invalid_target_));
    payloads_.push_back({at, packed, std::move(sorted_keys), std::move(sorted_targets), std::nullopt});
    used_packed_ |= packed;
    used_sparse_ |= !packed;
}

std::size_t CffSwitchEmitter::PlannedPayloadEnd(std::size_t start, std::uint16_t scratch_register) const {
    if (payloads_emitted_) throw std::logic_error("CFF payloads already emitted");
    for (const auto& payload : payloads_) {
        start = CffAssembler::AlignedPayloadPosition(start, scratch_register);
        const auto size = payload.packed ? 4U + 2U * payload.keys.size() : 2U + 4U * payload.keys.size();
        if (size > std::numeric_limits<std::size_t>::max() - start)
            throw std::length_error("CFF switch layout overflow");
        start += size;
    }
    return start;
}

void CffSwitchEmitter::EmitPayloads(std::uint16_t scratch_register) {
    if (payloads_emitted_) throw std::logic_error("CFF switch payloads emitted twice");
    payloads_emitted_ = true;
    const auto word = [&](std::uint32_t value) {
        assembler_->Emit({static_cast<std::uint16_t>(value), static_cast<std::uint16_t>(value >> 16U)});
    };
    for (auto& payload : payloads_) {
        assembler_->AlignPayload(scratch_register);
        payload.offset = assembler_->position();
        assembler_->Emit({static_cast<std::uint16_t>(payload.packed ? 0x0100U : 0x0200U),
                           static_cast<std::uint16_t>(payload.keys.size())});
        if (payload.packed) word(payload.keys.front());
        else for (auto key : payload.keys) word(key);
        for (auto target : payload.targets) {
            const auto position = assembler_->LabelPosition(target);
            if (!position) throw std::logic_error("CFF switch target is unbound");
            word(Displacement(*position, payload.instruction_offset));
        }
    }
}

void CffSwitchEmitter::PatchPayloads(std::vector<std::uint16_t>& units) const {
    if (!payloads_emitted_) throw std::logic_error("CFF switch payloads are missing");
    for (const auto& payload : payloads_) {
        const auto bits = Displacement(payload.offset.value(), payload.instruction_offset);
        units.at(payload.instruction_offset + 1U) = static_cast<std::uint16_t>(bits);
        units.at(payload.instruction_offset + 2U) = static_cast<std::uint16_t>(bits >> 16U);
    }
}
} // namespace birch::guard::detail
