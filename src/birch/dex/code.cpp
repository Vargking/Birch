#include "birch/dex/code.h"

#include "birch/dex/leb128.h"

#include <algorithm>
#include <limits>
#include <map>
#include <stdexcept>

namespace birch::dex {
namespace {

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) {
        throw DexParseError(DexErrorCode::Truncated, offset, "truncated code uint16");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t ReadU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        throw DexParseError(DexErrorCode::Truncated, offset, "truncated code uint32");
    }
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

Leb128Value ReadUlebChecked(std::span<const std::uint8_t> bytes, std::size_t offset) {
    try {
        return ReadUleb128(bytes, offset);
    } catch (const std::runtime_error& error) {
        throw DexParseError(DexErrorCode::InvalidClassData, offset, error.what());
    }
}

std::int32_t Signed32(std::uint16_t low, std::uint16_t high) {
    const auto raw = static_cast<std::uint32_t>(low) |
                     static_cast<std::uint32_t>(high) << 16U;
    return static_cast<std::int32_t>(raw);
}

std::uint32_t CheckedTarget(std::uint32_t base, std::int64_t relative,
                            std::uint32_t insns_size, std::size_t file_offset) {
    const auto target = static_cast<std::int64_t>(base) + relative;
    if (target < 0 || target >= insns_size) {
        throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                            "branch target is outside code item");
    }
    return static_cast<std::uint32_t>(target);
}

std::uint8_t StandardWidth(std::uint8_t opcode, std::uint8_t version,
                           std::size_t file_offset) {
    if (opcode == 0x00U || opcode == 0x01U || opcode == 0x04U || opcode == 0x07U ||
        (opcode >= 0x0aU && opcode <= 0x12U) || opcode == 0x1dU || opcode == 0x1eU ||
        opcode == 0x21U || opcode == 0x27U || opcode == 0x28U ||
        (opcode >= 0x7bU && opcode <= 0x8fU) ||
        (opcode >= 0xb0U && opcode <= 0xcfU)) {
        return 1U;
    }
    if (opcode == 0x02U || opcode == 0x05U || opcode == 0x08U || opcode == 0x13U ||
        opcode == 0x15U || opcode == 0x16U || opcode == 0x19U || opcode == 0x1aU ||
        opcode == 0x1cU || opcode == 0x1fU || opcode == 0x20U || opcode == 0x22U ||
        opcode == 0x23U || opcode == 0x29U || (opcode >= 0x2dU && opcode <= 0x3dU) ||
        (opcode >= 0x44U && opcode <= 0x6dU) ||
        (opcode >= 0x90U && opcode <= 0xafU) ||
        (opcode >= 0xd0U && opcode <= 0xe2U)) {
        return 2U;
    }
    if (opcode == 0x03U || opcode == 0x06U || opcode == 0x09U || opcode == 0x14U ||
        opcode == 0x17U || opcode == 0x1bU || (opcode >= 0x24U && opcode <= 0x26U) ||
        opcode == 0x2aU || opcode == 0x2bU || opcode == 0x2cU ||
        (opcode >= 0x6eU && opcode <= 0x72U) ||
        (opcode >= 0x74U && opcode <= 0x78U)) {
        return 3U;
    }
    if (opcode == 0x18U) {
        return 5U;
    }
    if (opcode >= 0xfaU) {
        if (version < 38U) {
            throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                                "DEX opcode is not valid for this version");
        }
        if (opcode == 0xfaU || opcode == 0xfbU) {
            return 4U;
        }
        return opcode == 0xfcU || opcode == 0xfdU ? 3U : 2U;
    }
    throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                        "reserved or unsupported DEX opcode");
}

bool CanThrow(std::uint8_t opcode) {
    return opcode == 0x1aU || opcode == 0x1bU || opcode == 0x1cU ||
           (opcode >= 0x1dU && opcode <= 0x27U) ||
           (opcode >= 0x44U && opcode <= 0x78U) ||
           opcode == 0x93U || opcode == 0x94U || opcode == 0x9eU || opcode == 0x9fU ||
           opcode == 0xb3U || opcode == 0xb4U || opcode == 0xbeU || opcode == 0xbfU ||
           opcode == 0xd3U || opcode == 0xd4U || opcode == 0xdbU || opcode == 0xdcU ||
           opcode >= 0xfaU;
}

std::vector<std::uint32_t> DecodeSwitchTargets(
    const std::vector<std::uint16_t>& insns, std::uint32_t switch_offset,
    std::uint32_t payload_offset, std::size_t file_offset) {
    if (payload_offset >= insns.size()) {
        throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                            "switch payload target is outside code item");
    }
    const auto ident = insns[payload_offset];
    if (ident != 0x0100U && ident != 0x0200U) {
        throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                            "switch target is not a switch payload");
    }
    if (payload_offset + 2U > insns.size()) {
        throw DexParseError(DexErrorCode::Truncated, file_offset,
                            "truncated switch payload");
    }
    const auto size = insns[payload_offset + 1U];
    const std::uint64_t targets_start = ident == 0x0100U
        ? static_cast<std::uint64_t>(payload_offset) + 4U
        : static_cast<std::uint64_t>(payload_offset) + 2U +
              static_cast<std::uint64_t>(size) * 2U;
    if (targets_start + static_cast<std::uint64_t>(size) * 2U > insns.size()) {
        throw DexParseError(DexErrorCode::Truncated, file_offset,
                            "truncated switch targets");
    }
    std::vector<std::uint32_t> targets;
    targets.reserve(size);
    for (std::uint32_t i = 0; i < size; ++i) {
        const auto at = static_cast<std::size_t>(targets_start) + i * 2U;
        targets.push_back(CheckedTarget(switch_offset,
                                        Signed32(insns[at], insns[at + 1U]),
                                        static_cast<std::uint32_t>(insns.size()),
                                        file_offset));
    }
    return targets;
}

std::uint32_t PayloadWidth(const std::vector<std::uint16_t>& insns,
                           std::uint32_t offset, std::size_t file_offset) {
    const auto ident = insns[offset];
    if (ident == 0x0100U) {
        if (offset + 2U > insns.size()) {
            throw DexParseError(DexErrorCode::Truncated, file_offset,
                                "truncated packed-switch payload");
        }
        return 4U + static_cast<std::uint32_t>(insns[offset + 1U]) * 2U;
    }
    if (ident == 0x0200U) {
        if (offset + 2U > insns.size()) {
            throw DexParseError(DexErrorCode::Truncated, file_offset,
                                "truncated sparse-switch payload");
        }
        return 2U + static_cast<std::uint32_t>(insns[offset + 1U]) * 4U;
    }
    if (ident == 0x0300U) {
        if (offset + 4U > insns.size()) {
            throw DexParseError(DexErrorCode::Truncated, file_offset,
                                "truncated fill-array-data payload");
        }
        const auto element_width = insns[offset + 1U];
        const auto element_count = static_cast<std::uint32_t>(insns[offset + 2U]) |
                                   static_cast<std::uint32_t>(insns[offset + 3U]) << 16U;
        const auto bytes = static_cast<std::uint64_t>(element_width) * element_count;
        const auto width = 4U + (bytes + 1U) / 2U;
        if (width > std::numeric_limits<std::uint32_t>::max()) {
            throw DexParseError(DexErrorCode::IntegerOverflow, file_offset,
                                "fill-array-data payload is too large");
        }
        return static_cast<std::uint32_t>(width);
    }
    if (ident == 0U) return 1U; // canonical nop
    throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                        "unknown payload pseudo-opcode");
}

} // namespace

CodeItem DecodeCodeItem(const DexFile& dex, std::uint32_t file_offset) {
    const auto bytes = dex.bytes();
    if (file_offset > bytes.size() || bytes.size() - file_offset < 16U) {
        throw DexParseError(DexErrorCode::OutOfBounds, file_offset,
                            "code_item header exceeds file");
    }
    CodeItem result;
    result.file_offset = file_offset;
    result.registers_size = ReadU16(bytes, file_offset);
    result.ins_size = ReadU16(bytes, file_offset + 2U);
    result.outs_size = ReadU16(bytes, file_offset + 4U);
    const auto tries_size = ReadU16(bytes, file_offset + 6U);
    result.debug_info_off = ReadU32(bytes, file_offset + 8U);
    const auto insns_size = ReadU32(bytes, file_offset + 12U);
    if (result.ins_size > result.registers_size) {
        throw DexParseError(DexErrorCode::InvalidClassData, file_offset,
                            "ins_size exceeds registers_size");
    }
    const auto insns_file_offset = static_cast<std::uint64_t>(file_offset) + 16U;
    const auto insns_bytes = static_cast<std::uint64_t>(insns_size) * 2U;
    if (insns_file_offset > bytes.size() || insns_bytes > bytes.size() - insns_file_offset) {
        throw DexParseError(DexErrorCode::OutOfBounds, file_offset + 12U,
                            "code instructions exceed file");
    }
    result.insns.reserve(insns_size);
    for (std::uint32_t i = 0; i < insns_size; ++i) {
        result.insns.push_back(ReadU16(bytes,
            static_cast<std::size_t>(insns_file_offset) + static_cast<std::size_t>(i) * 2U));
    }

    std::map<std::uint32_t, std::size_t> by_offset;
    std::uint32_t cursor = 0;
    while (cursor < insns_size) {
        DecodedInstruction instruction;
        instruction.offset = cursor;
        const auto first = result.insns[cursor];
        instruction.opcode = static_cast<std::uint8_t>(first & 0xffU);
        const auto instruction_file_offset = static_cast<std::size_t>(insns_file_offset) +
                                             static_cast<std::size_t>(cursor) * 2U;
        std::uint32_t width = 0;
        if (instruction.opcode == 0x00U) {
            width = PayloadWidth(result.insns, cursor, instruction_file_offset);
            instruction.kind = first == 0U ? InstructionKind::Normal : InstructionKind::Payload;
        } else {
            width = StandardWidth(instruction.opcode, dex.version(), instruction_file_offset);
            instruction.can_throw = CanThrow(instruction.opcode);
        }
        if (width == 0U || cursor > insns_size || width > insns_size - cursor) {
            throw DexParseError(DexErrorCode::Truncated, instruction_file_offset,
                                "instruction exceeds code item");
        }
        instruction.width = width;
        instruction.code_units.assign(result.insns.begin() + cursor,
                                      result.insns.begin() + cursor + width);

        if (instruction.opcode >= 0x0eU && instruction.opcode <= 0x11U) {
            instruction.kind = InstructionKind::Return;
        } else if (instruction.opcode == 0x27U) {
            instruction.kind = InstructionKind::Throw;
        } else if (instruction.opcode == 0x28U) {
            instruction.kind = InstructionKind::UnconditionalBranch;
            instruction.targets.push_back(CheckedTarget(cursor,
                static_cast<std::int8_t>(first >> 8U), insns_size, instruction_file_offset));
        } else if (instruction.opcode == 0x29U) {
            instruction.kind = InstructionKind::UnconditionalBranch;
            instruction.targets.push_back(CheckedTarget(cursor,
                static_cast<std::int16_t>(result.insns[cursor + 1U]), insns_size,
                instruction_file_offset));
        } else if (instruction.opcode == 0x2aU) {
            instruction.kind = InstructionKind::UnconditionalBranch;
            instruction.targets.push_back(CheckedTarget(cursor,
                Signed32(result.insns[cursor + 1U], result.insns[cursor + 2U]),
                insns_size, instruction_file_offset));
        } else if (instruction.opcode == 0x2bU || instruction.opcode == 0x2cU) {
            instruction.kind = InstructionKind::Switch;
            const auto payload = CheckedTarget(cursor,
                Signed32(result.insns[cursor + 1U], result.insns[cursor + 2U]),
                insns_size, instruction_file_offset);
            const auto expected_payload = instruction.opcode == 0x2bU ? 0x0100U : 0x0200U;
            if (result.insns[payload] != expected_payload) {
                throw DexParseError(DexErrorCode::InvalidClassData, instruction_file_offset,
                                    "switch opcode references the wrong payload type");
            }
            instruction.targets = DecodeSwitchTargets(result.insns, cursor, payload,
                                                       instruction_file_offset);
        } else if (instruction.opcode >= 0x32U && instruction.opcode <= 0x3dU) {
            instruction.kind = InstructionKind::ConditionalBranch;
            instruction.targets.push_back(CheckedTarget(cursor,
                static_cast<std::int16_t>(result.insns[cursor + 1U]), insns_size,
                instruction_file_offset));
        } else if (instruction.opcode == 0x26U) {
            const auto payload = CheckedTarget(cursor,
                Signed32(result.insns[cursor + 1U], result.insns[cursor + 2U]),
                insns_size, instruction_file_offset);
            if (result.insns[payload] != 0x0300U) {
                throw DexParseError(DexErrorCode::InvalidClassData, instruction_file_offset,
                                    "fill-array-data target is not a payload");
            }
        }
        by_offset.emplace(cursor, result.instructions.size());
        result.instructions.push_back(std::move(instruction));
        cursor += width;
    }
    for (const auto& instruction : result.instructions) {
        for (const auto target : instruction.targets) {
            if (!by_offset.contains(target) ||
                result.instructions[by_offset.at(target)].kind == InstructionKind::Payload) {
                throw DexParseError(DexErrorCode::InvalidClassData,
                                    static_cast<std::size_t>(insns_file_offset) +
                                        instruction.offset * 2U,
                                    "branch target is not an instruction boundary");
            }
        }
    }

    if (tries_size == 0U) {
        return result;
    }
    const auto padding = (insns_size & 1U) != 0U ? 2U : 0U;
    const auto tries_offset64 = insns_file_offset + insns_bytes + padding;
    const auto handlers_offset64 = tries_offset64 + static_cast<std::uint64_t>(tries_size) * 8U;
    if (handlers_offset64 > bytes.size()) {
        throw DexParseError(DexErrorCode::OutOfBounds, static_cast<std::size_t>(tries_offset64),
                            "try items exceed file");
    }
    const auto tries_offset = static_cast<std::size_t>(tries_offset64);
    const auto handlers_offset = static_cast<std::size_t>(handlers_offset64);
    std::map<std::uint32_t, std::vector<CatchHandler>> handlers;
    Leb128Value handlers_count;
    try {
        handlers_count = ReadUleb128(bytes, handlers_offset);
    } catch (const std::runtime_error& error) {
        throw DexParseError(DexErrorCode::InvalidClassData, handlers_offset, error.what());
    }
    std::size_t handler_cursor = handlers_offset + handlers_count.size;
    for (std::uint32_t i = 0; i < handlers_count.value; ++i) {
        const auto relative_offset = static_cast<std::uint32_t>(handler_cursor - handlers_offset);
        Sleb128Value size;
        try {
            size = ReadSleb128(bytes, handler_cursor);
        } catch (const std::runtime_error& error) {
            throw DexParseError(DexErrorCode::InvalidClassData, handler_cursor, error.what());
        }
        handler_cursor += size.size;
        const auto typed_count = size.value < 0 ? -static_cast<std::int64_t>(size.value)
                                                : static_cast<std::int64_t>(size.value);
        std::vector<CatchHandler> values;
        for (std::int64_t entry = 0; entry < typed_count; ++entry) {
            const auto type = ReadUlebChecked(bytes, handler_cursor); handler_cursor += type.size;
            const auto address = ReadUlebChecked(bytes, handler_cursor); handler_cursor += address.size;
            if (type.value >= dex.types().size() || address.value >= insns_size) {
                throw DexParseError(DexErrorCode::InvalidClassData, handler_cursor,
                                    "invalid encoded catch handler");
            }
            values.push_back({type.value, address.value});
        }
        if (size.value <= 0) {
            const auto address = ReadUlebChecked(bytes, handler_cursor); handler_cursor += address.size;
            if (address.value >= insns_size) {
                throw DexParseError(DexErrorCode::InvalidClassData, handler_cursor,
                                    "invalid catch-all handler");
            }
            values.push_back({std::nullopt, address.value});
        }
        handlers.emplace(relative_offset, std::move(values));
    }
    result.tries.reserve(tries_size);
    for (std::uint32_t i = 0; i < tries_size; ++i) {
        const auto offset = tries_offset + static_cast<std::size_t>(i) * 8U;
        const auto start = ReadU32(bytes, offset);
        const auto count = ReadU16(bytes, offset + 4U);
        const auto handler_offset = ReadU16(bytes, offset + 6U);
        if (count == 0U || start >= insns_size || count > insns_size - start) {
            throw DexParseError(DexErrorCode::InvalidClassData, offset,
                                "invalid try region");
        }
        const auto found = handlers.find(handler_offset);
        if (found == handlers.end()) {
            throw DexParseError(DexErrorCode::InvalidClassData, offset + 6U,
                                "try item references unknown handler");
        }
        if (!by_offset.contains(start) ||
            (start + count != insns_size && !by_offset.contains(start + count))) {
            throw DexParseError(DexErrorCode::InvalidClassData, offset,
                                "try region is not aligned to instruction boundaries");
        }
        for (const auto& handler : found->second) {
            const auto entry = by_offset.find(handler.address);
            if (entry == by_offset.end() ||
                result.instructions[entry->second].kind == InstructionKind::Payload) {
                throw DexParseError(DexErrorCode::InvalidClassData, offset + 6U,
                                    "catch handler is not an instruction boundary");
            }
        }
        result.tries.push_back({start, count, found->second});
    }
    return result;
}

} // namespace birch::dex
