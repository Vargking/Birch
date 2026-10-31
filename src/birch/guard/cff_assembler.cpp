#include "cff_assembler.h"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <stdexcept>
#include <utility>

namespace birch::guard::detail {

CffAssembler::Label CffAssembler::NewLabel() {
    labels_.push_back(std::nullopt);
    return labels_.size() - 1U;
}

void CffAssembler::Bind(Label label) {
    if (label >= labels_.size() || labels_[label].has_value()) {
        throw std::logic_error("invalid or duplicate CFF label");
    }
    labels_[label] = code_.size();
}

void CffAssembler::Emit(std::span<const std::uint16_t> units) {
    code_.insert(code_.end(), units.begin(), units.end());
}

void CffAssembler::Emit(std::initializer_list<std::uint16_t> units) {
    code_.insert(code_.end(), units.begin(), units.end());
}

void CffAssembler::EmitConst32(std::uint16_t reg, std::uint32_t value) {
    if (reg > 0xffU)
        throw std::length_error("CFF state register exceeds v255");
    const auto signed_value = std::bit_cast<std::int32_t>(value);
    if (reg <= 15U && signed_value >= -8 && signed_value <= 7) {
        Emit({static_cast<std::uint16_t>(0x12U | (reg << 8U) | ((value & 15U) << 12U))});
        return;
    }
    if (signed_value >= -32768 && signed_value <= 32767) {
        Emit({static_cast<std::uint16_t>(0x13U | (reg << 8U)), static_cast<std::uint16_t>(value)});
        return;
    }
    Emit({static_cast<std::uint16_t>(0x14U | (reg << 8U)), static_cast<std::uint16_t>(value),
          static_cast<std::uint16_t>(value >> 16U)});
}

void CffAssembler::EmitXor(std::uint16_t destination, std::uint16_t left, std::uint16_t right) {
    if (destination == right)
        std::swap(left, right);
    if (destination == left && destination <= 15U && right <= 15U) {
        Emit({static_cast<std::uint16_t>(0xb7U | (destination << 8U) | (right << 12U))});
        return;
    }
    Emit({static_cast<std::uint16_t>(0x97U | (destination << 8U)),
          static_cast<std::uint16_t>(left | (right << 8U))});
}

std::size_t CffAssembler::AlignedPayloadPosition(std::size_t position, std::uint16_t scratch_register) {
    const auto padding = (position & 1U) == 0U ? 0U : scratch_register <= 15U ? 1U : 3U;
    if (position > std::numeric_limits<std::size_t>::max() - padding)
        throw std::length_error("CFF payload alignment overflow");
    return position + padding;
}

void CffAssembler::AlignPayload(std::uint16_t scratch_register) {
    if ((position() & 1U) == 0U)
        return;
    // Both forms have odd width and define the destination; unlike a
    // move-to-self they are valid even in unreachable alignment islands.
    if (scratch_register <= 15U)
        EmitConst32(scratch_register, 0U);
    else
        Emit({static_cast<std::uint16_t>(0x14U | (scratch_register << 8U)), 0U, 0U});
}

void CffAssembler::EmitEncodedState(std::uint16_t reg, std::uint32_t value, std::uint64_t salt) {
    auto xor_key = static_cast<std::uint8_t>((salt >> 9U) | 1U);
    auto add_key = static_cast<std::uint8_t>((salt >> 33U) | 1U);
    const auto initial =
        (value -
         static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(add_key)))) ^
        static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<std::int8_t>(xor_key)));
    EmitConst32(reg, initial);
    Emit({static_cast<std::uint16_t>(0xdfU | (reg << 8U)),
          static_cast<std::uint16_t>(reg | (static_cast<std::uint16_t>(xor_key) << 8U)),
          static_cast<std::uint16_t>(0xd8U | (reg << 8U)),
          static_cast<std::uint16_t>(reg | (static_cast<std::uint16_t>(add_key) << 8U))});
}

void CffAssembler::EmitRuntimeEncodedState(std::uint16_t reg, std::uint32_t value,
                                           std::uint64_t salt,
                                           std::optional<std::uint16_t> barrier_method) {
    EmitEncodedState(reg, value, salt);
    if (!barrier_method.has_value())
        return;
    // invoke-static/range {vReg}, barrier(I)I; move-result vReg.
    // 3rc accepts the full register file, unlike invoke-static/35c.
    Emit({0x0177U, *barrier_method, reg, static_cast<std::uint16_t>(0x000aU | (reg << 8U))});
}

bool CffAssembler::EmitRelativeEncodedState(std::uint16_t reg, std::uint32_t current,
                                            std::uint32_t target, std::uint64_t salt) {
    if (reg > 0xffU)
        throw std::length_error("CFF state register exceeds v255");
    const auto signed_delta = [](std::uint32_t from, std::uint32_t to) {
        auto delta = static_cast<std::int64_t>(to) - static_cast<std::int64_t>(from);
        constexpr auto modulus = std::int64_t{1} << 32U;
        if (delta > std::numeric_limits<std::int32_t>::max())
            delta -= modulus;
        if (delta < std::numeric_limits<std::int32_t>::min())
            delta += modulus;
        return delta;
    };
    auto state = salt;
    for (std::size_t attempt = 0U; attempt < 64U; ++attempt) {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        auto xor_key = static_cast<std::int8_t>(state);
        if (xor_key == 0)
            xor_key = 1;
        const auto xor_bits = static_cast<std::uint32_t>(static_cast<std::int32_t>(xor_key));
        const auto intermediate = current ^ xor_bits;
        const auto add = signed_delta(intermediate, target);
        if (add < std::numeric_limits<std::int8_t>::min() ||
            add > std::numeric_limits<std::int8_t>::max()) {
            continue;
        }
        Emit(
            {static_cast<std::uint16_t>(0xdfU | (reg << 8U)),
             static_cast<std::uint16_t>(
                 reg | (static_cast<std::uint16_t>(static_cast<std::uint8_t>(xor_key)) << 8U)),
             static_cast<std::uint16_t>(0xd8U | (reg << 8U)),
             static_cast<std::uint16_t>(reg | (static_cast<std::uint16_t>(static_cast<std::uint8_t>(
                                                   static_cast<std::int8_t>(add)))
                                               << 8U))});
        return true;
    }

    const auto delta = signed_delta(current, target);
    if ((delta < -256 || delta > 254) && reg <= 15U && delta >= -65536 && delta <= 65534) {
        // 22s has four-bit registers and a signed 16-bit literal. Keep
        // two keyed operations, but avoid a full constant reload for
        // far-apart states in a large packed/mixed graph.
        const auto minimum = std::max<std::int64_t>(-32768, delta - 32767);
        const auto maximum = std::min<std::int64_t>(32767, delta + 32768);
        const auto first = minimum + static_cast<std::int64_t>(
                                         salt % static_cast<std::uint64_t>(maximum - minimum + 1));
        const auto second = delta - first;
        const auto instruction = static_cast<std::uint16_t>(0xd0U | (reg << 8U) | (reg << 12U));
        Emit({instruction, static_cast<std::uint16_t>(first), instruction,
              static_cast<std::uint16_t>(second)});
        return true;
    }
    if (delta < -256 || delta > 254)
        return false;
    const auto minimum_first =
        std::max<std::int64_t>(std::numeric_limits<std::int8_t>::min(), delta - 127);
    const auto maximum_first =
        std::min<std::int64_t>(std::numeric_limits<std::int8_t>::max(), delta + 128);
    if (minimum_first > maximum_first)
        return false;
    const auto span = static_cast<std::uint64_t>(maximum_first - minimum_first + 1);
    const auto first = minimum_first + static_cast<std::int64_t>(salt % span);
    const auto second = delta - first;
    Emit(
        {static_cast<std::uint16_t>(0xd8U | (reg << 8U)),
         static_cast<std::uint16_t>(
             reg |
             (static_cast<std::uint16_t>(static_cast<std::uint8_t>(static_cast<std::int8_t>(first)))
              << 8U)),
         static_cast<std::uint16_t>(0xd8U | (reg << 8U)),
         static_cast<std::uint16_t>(reg | (static_cast<std::uint16_t>(static_cast<std::uint8_t>(
                                               static_cast<std::int8_t>(second)))
                                           << 8U))});
    return true;
}

void CffAssembler::EmitGoto32(Label target) {
    if (compact_branches_) {
        EmitGoto16(target);
        return;
    }
    const auto at = code_.size();
    Emit({0x002aU, 0U, 0U});
    fixups_.push_back({at, target, FixupKind::Branch32});
}

void CffAssembler::EmitGoto16(Label target) {
    const auto at = code_.size();
    Emit({0x0029U, 0U});
    fixups_.push_back({at, target, FixupKind::Branch16});
}

void CffAssembler::EmitGoto8(Label target) {
    const auto at = code_.size();
    Emit({0x0028U});
    fixups_.push_back({at, target, FixupKind::Branch8});
}

void CffAssembler::EmitIf16(std::uint16_t first, Label target) {
    if (compact_branches_) {
        const auto at = code_.size();
        Emit({first, 0U});
        fixups_.push_back({at, target, FixupKind::Branch16});
        return;
    }
    const auto inverse = static_cast<std::uint16_t>(
        (first & 0xff00U) | InverseIfOpcode(static_cast<std::uint8_t>(first & 0xffU)));
    // DEX conditionals only have a signed 16-bit displacement. Encode a
    // distance-independent long conditional by skipping over goto/32 when
    // the inverse condition is true.
    Emit({inverse, 5U});
    EmitGoto32(target);
}

std::size_t CffAssembler::position() const noexcept { return code_.size(); }

const std::optional<std::size_t> &CffAssembler::LabelPosition(Label label) const {
    return labels_.at(label);
}

bool CffAssembler::HasBranchTo(Label label) const {
    return std::any_of(fixups_.begin(), fixups_.end(), [label](const auto& fixup) {
        return fixup.label == label;
    });
}

std::vector<std::uint16_t> CffAssembler::Finish() && {
    for (const auto &fixup : fixups_) {
        if (!labels_.at(fixup.label).has_value()) {
            throw std::logic_error("unbound CFF label");
        }
        const auto displacement =
            static_cast<std::int64_t>(*labels_[fixup.label]) - static_cast<std::int64_t>(fixup.at);
        if (fixup.kind == FixupKind::Branch8) {
            if (displacement == 0 || displacement < -128 || displacement > 127)
                throw std::length_error("CFF local branch exceeds int8");
            code_.at(fixup.at) = static_cast<std::uint16_t>(
                0x28U | ((static_cast<std::uint32_t>(displacement) & 0xffU) << 8U));
        } else if (fixup.kind == FixupKind::Branch16) {
            if (displacement < std::numeric_limits<std::int16_t>::min() ||
                displacement > std::numeric_limits<std::int16_t>::max()) {
                throw std::length_error("CFF conditional displacement exceeds int16");
            }
            code_.at(fixup.at + 1U) =
                static_cast<std::uint16_t>(static_cast<std::int16_t>(displacement));
        } else {
            if (displacement < std::numeric_limits<std::int32_t>::min() ||
                displacement > std::numeric_limits<std::int32_t>::max()) {
                throw std::length_error("CFF branch displacement exceeds int32");
            }
            const auto bits = static_cast<std::uint32_t>(static_cast<std::int32_t>(displacement));
            code_.at(fixup.at + 1U) = static_cast<std::uint16_t>(bits);
            code_.at(fixup.at + 2U) = static_cast<std::uint16_t>(bits >> 16U);
        }
    }
    return std::move(code_);
}

std::uint16_t InverseIfOpcode(std::uint8_t opcode) {
    static constexpr std::array<std::uint8_t, 12U> inverse{
        0x33U, 0x32U, 0x35U, 0x34U, 0x37U, 0x36U, 0x39U, 0x38U, 0x3bU, 0x3aU, 0x3dU, 0x3cU,
    };
    if (opcode < 0x32U || opcode > 0x3dU) {
        throw std::invalid_argument("CFF expected an if instruction");
    }
    return inverse[opcode - 0x32U];
}

} // namespace birch::guard::detail
