#include "birch/dex/remap.h"

#include "birch/dex/checksum.h"
#include "birch/dex/code.h"
#include "birch/dex/ir.h"
#include "birch/dex/leb128.h"
#include "birch/dex/verifier.h"
#include "region_replacement.h"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace birch::dex {
namespace {

std::vector<std::uint32_t> Identity(std::size_t size) {
    std::vector<std::uint32_t> result(size);
    for (std::size_t i = 0; i < size; ++i) result[i] = static_cast<std::uint32_t>(i);
    return result;
}

std::uint32_t LinearInstructionWidth(std::uint8_t opcode, std::uint8_t version) {
    if (opcode == 0x00U || opcode == 0x01U || opcode == 0x04U ||
        opcode == 0x07U || (opcode >= 0x0aU && opcode <= 0x12U) ||
        opcode == 0x1dU || opcode == 0x1eU || opcode == 0x21U ||
        (opcode >= 0x7bU && opcode <= 0x8fU) ||
        (opcode >= 0xb0U && opcode <= 0xcfU)) {
        return 1U;
    }
    if (opcode == 0x02U || opcode == 0x05U || opcode == 0x08U ||
        opcode == 0x13U || opcode == 0x15U || opcode == 0x16U ||
        opcode == 0x19U || opcode == 0x1aU || opcode == 0x1cU ||
        opcode == 0x1fU || opcode == 0x20U || opcode == 0x22U ||
        opcode == 0x23U || opcode == 0x29U ||
        (opcode >= 0x2dU && opcode <= 0x3dU) ||
        (opcode >= 0x44U && opcode <= 0x6dU) ||
        (opcode >= 0x90U && opcode <= 0xafU) ||
        (opcode >= 0xd0U && opcode <= 0xe2U)) {
        return 2U;
    }
    if (opcode == 0x03U || opcode == 0x06U || opcode == 0x09U ||
        opcode == 0x14U || opcode == 0x17U || opcode == 0x1bU ||
        (opcode >= 0x24U && opcode <= 0x26U) || opcode == 0x2aU ||
        opcode == 0x2bU || opcode == 0x2cU ||
        (opcode >= 0x6eU && opcode <= 0x72U) ||
        (opcode >= 0x74U && opcode <= 0x78U)) {
        return 3U;
    }
    if (opcode == 0x18U) return 5U;
    if (opcode >= 0xfaU && version >= 38U) {
        if (opcode == 0xfaU || opcode == 0xfbU) return 4U;
        return opcode == 0xfcU || opcode == 0xfdU ? 3U : 2U;
    }
    throw std::invalid_argument(
        "linear replacement contains a reserved DEX opcode");
}

void ValidateLinearReplacement(std::span<const std::uint16_t> replacement,
                               std::uint8_t version) {
    std::size_t cursor = 0U;
    while (cursor < replacement.size()) {
        const auto first = replacement[cursor];
        const auto opcode = static_cast<std::uint8_t>(first & 0xffU);
        // A one-unit goto/8 to the immediately following instruction is a
        // verifier-safe semantic replacement for a canonical nop.
        if (opcode == 0x28U && first == 0x0128U &&
            replacement.size() == 1U) {
            ++cursor;
            continue;
        }
        if ((opcode == 0x00U && first != 0U) || opcode == 0x26U ||
            opcode == 0x27U || (opcode >= 0x28U && opcode <= 0x3dU) ||
            (opcode >= 0x0eU && opcode <= 0x11U)) {
            throw std::invalid_argument(
                "linear replacement contains control flow or a payload");
        }
        const auto width = LinearInstructionWidth(opcode, version);
        if (width > replacement.size() - cursor) {
            throw std::invalid_argument(
                "linear replacement instruction is truncated");
        }
        cursor += width;
    }
}

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) {
        throw DexParseError(DexErrorCode::Truncated, offset, "truncated uint16 during ID remap");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U;
}

std::uint32_t ReadU32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        throw DexParseError(DexErrorCode::Truncated, offset, "truncated uint32 during ID remap");
    }
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

void WriteU16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) {
        throw DexParseError(DexErrorCode::OutOfBounds, offset, "uint16 ID patch exceeds DEX");
    }
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void WriteU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    if (offset > bytes.size() || bytes.size() - offset < 4U) {
        throw DexParseError(DexErrorCode::OutOfBounds, offset, "uint32 ID patch exceeds DEX");
    }
    for (unsigned shift = 0U; shift < 32U; shift += 8U) {
        bytes[offset + shift / 8U] = static_cast<std::uint8_t>(value >> shift);
    }
}

std::vector<std::uint8_t> EncodeUleb(std::uint32_t value) {
    std::vector<std::uint8_t> result;
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U);
        result.push_back(byte);
    } while (value != 0U);
    return result;
}

std::vector<std::uint8_t> EncodeSleb(std::int32_t value) {
    std::vector<std::uint8_t> result;
    bool more = true;
    while (more) {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        const auto sign = (byte & 0x40U) != 0U;
        value >>= 7;
        more = !((value == 0 && !sign) || (value == -1 && sign));
        if (more) byte = static_cast<std::uint8_t>(byte | 0x80U);
        result.push_back(byte);
    }
    return result;
}

std::vector<std::uint32_t> InversePermutation(const std::vector<std::uint32_t>& remap,
                                              std::string_view label) {
    std::vector<std::uint32_t> inverse(remap.size(), 0U);
    std::vector<bool> seen(remap.size(), false);
    for (std::size_t old = 0; old < remap.size(); ++old) {
        if (remap[old] >= remap.size() || seen[remap[old]]) {
            throw std::invalid_argument(std::string(label) + " remap is not a permutation");
        }
        seen[remap[old]] = true;
        inverse[remap[old]] = static_cast<std::uint32_t>(old);
    }
    return inverse;
}

bool IsIdentity(const std::vector<std::uint32_t>& values) {
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (values[i] != i) return false;
    }
    return true;
}

std::vector<std::uint16_t> Mutf8Key(std::string_view value) {
    std::vector<std::uint16_t> result;
    for (std::size_t cursor = 0; cursor < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[cursor]);
        std::uint32_t code_unit = 0U;
        std::size_t width = 0U;
        if (first <= 0x7fU) {
            code_unit = first;
            width = 1U;
        } else if (first >= 0xc0U && first <= 0xdfU) {
            code_unit = first & 0x1fU;
            width = 2U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            code_unit = first & 0x0fU;
            width = 3U;
        } else {
            throw std::runtime_error("invalid MUTF-8 leading byte in canonical sort");
        }
        if (cursor + width > value.size()) {
            throw std::runtime_error("truncated MUTF-8 in canonical sort");
        }
        for (std::size_t i = 1U; i < width; ++i) {
            const auto next = static_cast<std::uint8_t>(value[cursor + i]);
            if ((next & 0xc0U) != 0x80U) {
                throw std::runtime_error("invalid MUTF-8 continuation in canonical sort");
            }
            code_unit = (code_unit << 6U) | (next & 0x3fU);
        }
        result.push_back(static_cast<std::uint16_t>(code_unit));
        cursor += width;
    }
    return result;
}

std::vector<std::uint8_t> RewritePrimaryIds(
    const DexFile& dex, const IdRemap& remap,
    const std::map<std::uint32_t, CodePrefix>* code_prefixes = nullptr,
    CodeAddressMaps* addresses = nullptr) {
    const auto old_string = InversePermutation(remap.strings, "string");
    const auto old_type = InversePermutation(remap.types, "type");
    const auto old_proto = InversePermutation(remap.protos, "proto");
    auto result = std::vector<std::uint8_t>(dex.bytes().begin(), dex.bytes().end());
    const auto source = dex.bytes();
    const auto& header = dex.header();
    const auto aliased_string = [&](std::uint32_t old_index) {
        return remap.string_aliases.empty() ? old_index :
               remap.string_aliases.at(old_index);
    };
    const auto mapped_string = [&](std::uint32_t old_index) {
        return remap.strings.at(aliased_string(old_index));
    };
    auto reference_string_remap = remap.strings;
    for (std::size_t old_index = 0U; old_index < reference_string_remap.size(); ++old_index) {
        reference_string_remap[old_index] = mapped_string(static_cast<std::uint32_t>(old_index));
    }

    for (std::uint32_t new_index = 0; new_index < old_string.size(); ++new_index) {
        WriteU32(result, static_cast<std::size_t>(header.string_ids_off) + new_index * 4U,
                 dex.strings()[old_string[new_index]].data_offset);
    }
    for (std::uint32_t new_index = 0; new_index < old_type.size(); ++new_index) {
        const auto& value = dex.types()[old_type[new_index]];
        WriteU32(result, static_cast<std::size_t>(header.type_ids_off) + new_index * 4U,
                 remap.strings[value.descriptor_idx]);
    }
    for (std::uint32_t new_index = 0; new_index < old_proto.size(); ++new_index) {
        const auto& value = dex.protos()[old_proto[new_index]];
        const auto offset = static_cast<std::size_t>(header.proto_ids_off) + new_index * 12U;
        WriteU32(result, offset, remap.strings[value.shorty_idx]);
        WriteU32(result, offset + 4U, remap.types[value.return_type_idx]);
        WriteU32(result, offset + 8U, value.parameters_off);
    }
    for (std::uint32_t index = 0; index < dex.fields().size(); ++index) {
        const auto& value = dex.fields()[index];
        const auto offset = static_cast<std::size_t>(header.field_ids_off) + index * 8U;
        WriteU16(result, offset, static_cast<std::uint16_t>(remap.types[value.class_idx]));
        WriteU16(result, offset + 2U, static_cast<std::uint16_t>(remap.types[value.type_idx]));
        WriteU32(result, offset + 4U, mapped_string(value.name_idx));
    }
    for (std::uint32_t index = 0; index < dex.methods().size(); ++index) {
        const auto& value = dex.methods()[index];
        const auto offset = static_cast<std::size_t>(header.method_ids_off) + index * 8U;
        WriteU16(result, offset, static_cast<std::uint16_t>(remap.types[value.class_idx]));
        WriteU16(result, offset + 2U, static_cast<std::uint16_t>(remap.protos[value.proto_idx]));
        WriteU32(result, offset + 4U, mapped_string(value.name_idx));
    }

    struct ClassRecord {
        std::array<std::uint8_t, 32> bytes{};
        std::uint32_t class_idx{};
    };
    std::vector<ClassRecord> class_records;
    class_records.reserve(dex.classes().size());
    for (std::size_t index = 0; index < dex.classes().size(); ++index) {
        const auto source_offset = static_cast<std::size_t>(header.class_defs_off) + index * 32U;
        ClassRecord record;
        std::copy_n(source.begin() + source_offset, 32U, record.bytes.begin());
        const auto& definition = dex.classes()[index];
        record.class_idx = remap.types[definition.class_idx];
        auto patch_record_u32 = [&](std::size_t offset, std::uint32_t value) {
            for (unsigned shift = 0U; shift < 32U; shift += 8U) {
                record.bytes[offset + shift / 8U] = static_cast<std::uint8_t>(value >> shift);
            }
        };
        patch_record_u32(0U, record.class_idx);
        if (definition.superclass_idx != std::numeric_limits<std::uint32_t>::max()) {
            patch_record_u32(8U, remap.types[definition.superclass_idx]);
        }
        if (definition.source_file_idx != std::numeric_limits<std::uint32_t>::max()) {
            patch_record_u32(16U, remap.strings[definition.source_file_idx]);
        }
        class_records.push_back(record);
    }
    std::set<std::uint32_t> defined_class_indices;
    for (const auto& record : class_records) {
        if (!defined_class_indices.insert(record.class_idx).second) {
            throw std::runtime_error("class definition remap produced a duplicate class index");
        }
    }
    for (std::size_t index = 0; index < class_records.size(); ++index) {
        std::copy(class_records[index].bytes.begin(), class_records[index].bytes.end(),
                  result.begin() + header.class_defs_off + index * 32U);
    }

    for (const auto& item : dex.map()) {
        if (item.type != 0x1001U) continue;
        std::size_t cursor = item.offset;
        for (std::uint32_t list = 0; list < item.size; ++list) {
            const auto count = ReadU32(source, cursor);
            cursor += 4U;
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto old_index = ReadU16(source, cursor);
                if (old_index >= remap.types.size()) {
                    throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                        "type_list index is invalid during remap");
                }
                WriteU16(result, cursor, static_cast<std::uint16_t>(remap.types[old_index]));
                cursor += 2U;
            }
            cursor = (cursor + 3U) & ~std::size_t{3U};
        }
    }

    auto read_uleb = [&](std::size_t& cursor) {
        const auto value = ReadUleb128(source, cursor);
        cursor += value.size;
        return value.value;
    };
    const auto append_uleb = [](std::vector<std::uint8_t>& output, std::uint32_t value) {
        const auto encoded = EncodeUleb(value);
        output.insert(output.end(), encoded.begin(), encoded.end());
    };
    const auto append_index = [](std::vector<std::uint8_t>& output, std::uint8_t value_type,
                                 std::uint32_t value, std::uint8_t minimum_width = 1U) {
        std::uint8_t width = minimum_width;
        while (width < 4U && value >= (1U << (width * 8U))) ++width;
        output.push_back(static_cast<std::uint8_t>(value_type | ((width - 1U) << 5U)));
        for (std::uint8_t i = 0; i < width; ++i) {
            output.push_back(static_cast<std::uint8_t>(value >> (i * 8U)));
        }
    };
    const auto read_fixed_index = [&](std::size_t& cursor, std::uint8_t width,
                                      std::size_t count, std::string_view label) {
        if (cursor > source.size() || source.size() - cursor < width) {
            throw DexParseError(DexErrorCode::Truncated, cursor,
                                std::string(label) + " encoded index truncated");
        }
        std::uint32_t value = 0U;
        for (std::uint8_t i = 0; i < width; ++i) {
            value |= static_cast<std::uint32_t>(source[cursor + i]) << (i * 8U);
        }
        if (value >= count) {
            throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                std::string(label) + " encoded index invalid");
        }
        cursor += width;
        return value;
    };

    struct CodeItemRelocation {
        std::uint32_t old_offset{};
        std::uint32_t new_offset{};
        std::uint32_t old_debug_offset{};
        std::vector<std::uint32_t> address_map;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<CodeItemRelocation> code_items;
    for (const auto &map_item : dex.map()) {
      if (map_item.type != 0x2001U)
        continue;
      std::size_t cursor = map_item.offset;
      for (std::uint32_t item_index = 0; item_index < map_item.size;
           ++item_index) {
        cursor = (cursor + 3U) & ~std::size_t{3U};
        const auto old_offset = static_cast<std::uint32_t>(cursor);
        const auto registers_size = ReadU16(source, old_offset);
        const auto tries_size = ReadU16(source, old_offset + 6U);
        const auto old_debug_offset = ReadU32(source, old_offset + 8U);
        const auto insns_size = ReadU32(source, old_offset + 12U);
        const auto insns_end = static_cast<std::size_t>(old_offset) + 16U +
                               static_cast<std::size_t>(insns_size) * 2U;
        if (insns_end > source.size()) {
          throw DexParseError(
              DexErrorCode::Truncated, old_offset,
              "code_item instructions truncated during relocation");
        }
        const auto decoded = DecodeCodeItem(dex, old_offset);
        static const CodePrefix kNoPrefix;
        const auto prefix_it =
            code_prefixes == nullptr
                ? std::map<std::uint32_t, CodePrefix>::const_iterator{}
                : code_prefixes->find(old_offset);
        auto prefix_spec =
            code_prefixes != nullptr && prefix_it != code_prefixes->end()
                ? prefix_it->second
                : kNoPrefix;
        auto erased_arithmetic = detail::PrepareOutlineReplacements(decoded, prefix_spec);
        std::set<std::uint32_t> entry_boundaries;
        if (!prefix_spec.arithmetic_span_ends.empty()) {
          for (const auto& instruction : decoded.instructions)
            entry_boundaries.insert(instruction.targets.begin(), instruction.targets.end());
          for (const auto& region : decoded.tries) {
            entry_boundaries.insert(region.start_address);
            entry_boundaries.insert(region.start_address + region.instruction_count);
            for (const auto& handler : region.handlers) entry_boundaries.insert(handler.address);
          }
        }
        for (const auto& [start, end] : prefix_spec.arithmetic_span_ends) {
          auto first = std::find_if(decoded.instructions.begin(), decoded.instructions.end(),
              [&](const auto& instruction) { return instruction.offset == start; });
          if (first == decoded.instructions.end() || first->opcode != 0x14U ||
              end <= start + first->width || end > decoded.insns.size() ||
              !prefix_spec.linear_replacements.contains(start) ||
              prefix_spec.linear_replacements.at(start).empty())
            throw std::invalid_argument("invalid arithmetic replacement span");
          const auto reg = static_cast<std::uint32_t>(first->code_units.front() >> 8U);
          auto span_instruction = std::next(first);
          for (; span_instruction != decoded.instructions.end() && span_instruction->offset < end; ++span_instruction) {
            const auto unit = span_instruction->code_units.front();
            if ((span_instruction->opcode != 0xd0U && span_instruction->opcode != 0xd7U) ||
                ((unit >> 8U) & 0xfU) != reg || static_cast<std::uint32_t>(unit >> 12U) != reg ||
                entry_boundaries.contains(span_instruction->offset) ||
                prefix_spec.linear_replacements.contains(span_instruction->offset))
              throw std::invalid_argument("arithmetic replacement span crosses a live boundary");
            erased_arithmetic.insert(span_instruction->offset);
            prefix_spec.linear_replacements.emplace(span_instruction->offset, std::vector<std::uint16_t>{});
          }
          if (span_instruction == decoded.instructions.end() || span_instruction->offset != end)
            throw std::invalid_argument("arithmetic replacement span end is not an instruction boundary");
        }
        const auto &prefix = prefix_spec.code_units;
        if (prefix_spec.replacement_code_units.has_value() &&
            (!prefix.empty() || !prefix_spec.try_regions.empty() ||
             prefix_spec.reorder_blocks ||
             !prefix_spec.linear_replacements.empty())) {
          throw std::invalid_argument("complete code replacement cannot be "
                                      "combined with prefix rewriting");
        }
        if (!prefix.empty() &&
            (decoded.instructions.empty() ||
             decoded.instructions.front().offset != 0U ||
             decoded.instructions.front().kind == InstructionKind::Payload)) {
          throw std::invalid_argument("code prefix requires an executable "
                                      "instruction at method offset zero");
        }
        for (const auto &[replace_offset, replacement] :
             prefix_spec.linear_replacements) {
          const auto found = std::find_if(
              decoded.instructions.begin(), decoded.instructions.end(),
              [&](const auto &instruction) {
                return instruction.offset == replace_offset;
              });
          if (found == decoded.instructions.end()) {
            throw std::invalid_argument(
                "linear replacement offset is not an executable instruction");
          }
          if (replacement.empty()) {
            if (erased_arithmetic.contains(replace_offset)) continue;
            throw std::invalid_argument(
                "linear instruction replacement must not be empty");
          }
          if (found->kind == InstructionKind::Payload) {
            if (replacement.size() != found->width ||
                std::any_of(replacement.begin(), replacement.end(),
                            [](const auto unit) { return unit != 0U; })) {
              throw std::invalid_argument(
                  "payload replacement must be an equal-width nop sequence");
            }
          } else {
            ValidateLinearReplacement(replacement, dex.version());
          }
        }
        enum class BranchForm : std::uint8_t {
          Original,
          Goto16,
          Goto32,
          LongIf
        };
        std::vector<BranchForm> forms(decoded.instructions.size(),
                                      BranchForm::Original);
        std::vector<bool> promote_jumbo(decoded.instructions.size(), false);
        std::map<std::uint32_t, std::uint32_t> payload_sources;
        std::map<std::uint32_t, std::size_t> instruction_indices;
        const auto signed32 = [](std::uint16_t low, std::uint16_t high) {
          return static_cast<std::int32_t>(static_cast<std::uint32_t>(low) |
                                           static_cast<std::uint32_t>(high)
                                               << 16U);
        };
        for (std::size_t i = 0U; i < decoded.instructions.size(); ++i) {
          const auto &instruction = decoded.instructions[i];
          instruction_indices.emplace(instruction.offset, i);
          if (instruction.opcode == 0x1aU) {
            promote_jumbo[i] =
                mapped_string(instruction.code_units.at(1U)) > 0xffffU;
          }
          if (instruction.opcode == 0x2bU || instruction.opcode == 0x2cU ||
              instruction.opcode == 0x26U) {
            const auto relative = signed32(instruction.code_units.at(1U),
                                           instruction.code_units.at(2U));
            const auto payload64 =
                static_cast<std::int64_t>(instruction.offset) + relative;
            if (payload64 < 0 || payload64 >= insns_size) {
              throw DexParseError(DexErrorCode::InvalidClassData, old_offset,
                                  "payload reference is outside code item");
            }
            const auto payload = static_cast<std::uint32_t>(payload64);
            const auto [found, inserted] =
                payload_sources.emplace(payload, instruction.offset);
            if (!inserted && found->second != instruction.offset) {
              throw DexParseError(
                  DexErrorCode::InvalidClassData, old_offset,
                  "instruction payload is shared by multiple users");
            }
          }
        }

        std::vector<std::size_t> layout_order;
        std::vector<bool> seal_unreachable_chain_after(
            decoded.instructions.size(), false);
        layout_order.reserve(decoded.instructions.size());
        if (prefix_spec.reorder_blocks && decoded.tries.empty() &&
            old_debug_offset == 0U) {
          const auto ir = BuildMethodIr(decoded);
          std::vector<std::optional<BlockId>> fallthrough(ir.blocks().size());
          std::vector<bool> has_fallthrough_predecessor(ir.blocks().size(),
                                                        false);
          for (const auto &block : ir.blocks()) {
            for (const auto &edge : block.successors) {
              if (edge.kind != IrEdgeKind::Fallthrough)
                continue;
              if (fallthrough.at(block.id).has_value()) {
                throw std::logic_error(
                    "CFG block has multiple fallthrough successors");
              }
              fallthrough.at(block.id) = edge.target;
              has_fallthrough_predecessor.at(edge.target) = true;
            }
          }
          std::vector<std::vector<BlockId>> chains;
          std::vector<bool> visited(ir.blocks().size(), false);
          const auto build_chain = [&](BlockId start) {
            std::vector<BlockId> chain;
            auto current = start;
            while (!visited.at(current)) {
              visited.at(current) = true;
              chain.push_back(current);
              if (!fallthrough.at(current).has_value())
                break;
              current = *fallthrough.at(current);
            }
            return chain;
          };
          chains.push_back(build_chain(ir.entry()));
          std::vector<BlockId> roots;
          for (const auto &block : ir.blocks()) {
            if (block.id != ir.entry() &&
                !has_fallthrough_predecessor.at(block.id)) {
              roots.push_back(block.id);
            }
          }
          const auto mixed = [&](BlockId id) {
            auto value =
                prefix_spec.reorder_seed ^
                (static_cast<std::uint64_t>(ir.blocks().at(id).start_offset) +
                 0x9e3779b97f4a7c15ULL);
            value ^= value >> 30U;
            value *= 0xbf58476d1ce4e5b9ULL;
            value ^= value >> 27U;
            value *= 0x94d049bb133111ebULL;
            return value ^ (value >> 31U);
          };
          std::sort(roots.begin(), roots.end(),
                    [&](BlockId left, BlockId right) {
                      return std::tuple(mixed(left), left) <
                             std::tuple(mixed(right), right);
                    });
          if (roots.size() > 1U &&
              std::is_sorted(roots.begin(), roots.end(),
                             [&](BlockId left, BlockId right) {
                               return ir.blocks().at(left).start_offset <
                                      ir.blocks().at(right).start_offset;
                             })) {
            std::rotate(roots.begin(), roots.begin() + 1U, roots.end());
          }
          for (const auto root : roots) {
            if (!visited.at(root))
              chains.push_back(build_chain(root));
          }
          for (const auto &block : ir.blocks()) {
            if (!visited.at(block.id))
              chains.push_back(build_chain(block.id));
          }
          std::vector<bool> reachable(ir.blocks().size(), false);
          std::vector<BlockId> pending{ir.entry()};
          while (!pending.empty()) {
            const auto block = pending.back();
            pending.pop_back();
            if (reachable.at(block))
              continue;
            reachable.at(block) = true;
            for (const auto &edge : ir.blocks().at(block).successors) {
              if (!reachable.at(edge.target))
                pending.push_back(edge.target);
            }
          }
          for (const auto &chain : chains) {
            if (chain.empty())
              continue;
            const auto last_block = chain.back();
            const auto &last_ir = ir.blocks().at(last_block).instructions.back();
            const auto last_index = instruction_indices.at(last_ir.dex_offset);
            const auto &last = decoded.instructions.at(last_index);
            // A legal DEX may contain verifier-safe executable alignment
            // islands immediately before a payload. They have no CFG
            // successor and are unreachable from the method entry. Moving
            // such an island between two live chains must not invent a new
            // fallthrough edge into the following chain.
            if (!reachable.at(last_block) &&
                !fallthrough.at(last_block).has_value() &&
                last.kind == InstructionKind::Normal) {
              seal_unreachable_chain_after.at(last_index) = true;
            }
          }
          for (const auto &chain : chains) {
            for (const auto block_id : chain) {
              for (const auto &instruction :
                   ir.blocks().at(block_id).instructions) {
                layout_order.push_back(
                    instruction_indices.at(instruction.dex_offset));
              }
            }
          }
          for (std::size_t i = 0U; i < decoded.instructions.size(); ++i) {
            if (decoded.instructions[i].kind == InstructionKind::Payload) {
              layout_order.push_back(i);
            }
          }
          if (layout_order.size() != decoded.instructions.size()) {
            throw std::logic_error(
                "block reordering lost or duplicated a DEX instruction");
          }
        } else {
          for (std::size_t i = 0U; i < decoded.instructions.size(); ++i) {
            layout_order.push_back(i);
          }
        }

        std::vector<std::uint32_t> address_map(
            insns_size + 1U, std::numeric_limits<std::uint32_t>::max());
        std::vector<std::uint32_t> instruction_addresses(
            decoded.instructions.size(), 0U);
        const auto rebuild_address_map = [&]() {
          std::fill(address_map.begin(), address_map.end(),
                    std::numeric_limits<std::uint32_t>::max());
          std::uint64_t next = 0U;
          for (std::size_t order_index = 0U; order_index < layout_order.size();
               ++order_index) {
            const auto i = layout_order[order_index];
            const auto &instruction = decoded.instructions[i];
            if (order_index == 0U)
              next += prefix.size();
            if (instruction.kind == InstructionKind::Payload &&
                (next & 1U) != 0U)
              ++next;
            if (next > std::numeric_limits<std::uint32_t>::max()) {
              throw std::length_error(
                  "rewritten code_item exceeds uint32 code units");
            }
            address_map.at(instruction.offset) =
                static_cast<std::uint32_t>(next);
            instruction_addresses[i] = static_cast<std::uint32_t>(next);
            auto width = instruction.width;
            const auto replacement =
                prefix_spec.linear_replacements.find(instruction.offset);
            if (replacement != prefix_spec.linear_replacements.end()) {
              width = static_cast<std::uint32_t>(replacement->second.size());
            }
            if (promote_jumbo[i] && replacement == prefix_spec.linear_replacements.end())
              width = 3U;
            if (forms[i] == BranchForm::Goto16)
              width = 2U;
            else if (forms[i] == BranchForm::Goto32)
              width = 3U;
            else if (forms[i] == BranchForm::LongIf)
              width = 5U;
            next += width;
            if (seal_unreachable_chain_after.at(i))
              next += 3U; // goto/32 self
          }
          if (next > std::numeric_limits<std::uint32_t>::max()) {
            throw std::length_error(
                "rewritten code_item exceeds uint32 code units");
          }
          address_map.at(insns_size) = static_cast<std::uint32_t>(next);
        };
        const auto mapped_address = [&](std::uint32_t old_address) {
          if (old_address >= address_map.size() ||
              address_map[old_address] ==
                  std::numeric_limits<std::uint32_t>::max()) {
            throw DexParseError(
                DexErrorCode::InvalidClassData, old_offset,
                "relocated code address is not an instruction boundary");
          }
          return address_map[old_address];
        };
        const auto instruction_address = [&](std::uint32_t old_address) {
          const auto found = instruction_indices.find(old_address);
          if (found == instruction_indices.end()) {
            throw DexParseError(
                DexErrorCode::InvalidClassData, old_offset,
                "source address is not an instruction boundary");
          }
          return instruction_addresses.at(found->second);
        };
        bool relaxed = true;
        while (relaxed) {
          relaxed = false;
          rebuild_address_map();
          for (std::size_t i = 0U; i < decoded.instructions.size(); ++i) {
            const auto &instruction = decoded.instructions[i];
            if (instruction.targets.empty() || prefix_spec.linear_replacements.contains(instruction.offset))
              continue;
            const auto displacement = static_cast<std::int64_t>(mapped_address(
                                          instruction.targets.front())) -
                                      instruction_addresses[i];
            if (instruction.opcode == 0x28U &&
                forms[i] == BranchForm::Original &&
                (displacement < std::numeric_limits<std::int8_t>::min() ||
                 displacement > std::numeric_limits<std::int8_t>::max())) {
              forms[i] =
                  displacement >= std::numeric_limits<std::int16_t>::min() &&
                          displacement <=
                              std::numeric_limits<std::int16_t>::max()
                      ? BranchForm::Goto16
                      : BranchForm::Goto32;
              relaxed = true;
            } else if ((instruction.opcode == 0x29U ||
                        forms[i] == BranchForm::Goto16) &&
                       forms[i] != BranchForm::Goto32 &&
                       (displacement <
                            std::numeric_limits<std::int16_t>::min() ||
                        displacement >
                            std::numeric_limits<std::int16_t>::max())) {
              forms[i] = BranchForm::Goto32;
              relaxed = true;
            } else if (instruction.opcode >= 0x32U &&
                       instruction.opcode <= 0x3dU &&
                       forms[i] == BranchForm::Original &&
                       (displacement <
                            std::numeric_limits<std::int16_t>::min() ||
                        displacement >
                            std::numeric_limits<std::int16_t>::max())) {
              forms[i] = BranchForm::LongIf;
              relaxed = true;
            }
          }
        }
        rebuild_address_map();

        std::vector<std::uint16_t> rewritten_insns;
        rewritten_insns.reserve(address_map.back());
        rewritten_insns.insert(rewritten_insns.end(), prefix.begin(),
                               prefix.end());
        const auto append_i32 = [&](std::int64_t value) {
          if (value < std::numeric_limits<std::int32_t>::min() ||
              value > std::numeric_limits<std::int32_t>::max()) {
            throw std::length_error("DEX branch displacement exceeds int32");
          }
          const auto bits =
              static_cast<std::uint32_t>(static_cast<std::int32_t>(value));
          rewritten_insns.push_back(static_cast<std::uint16_t>(bits));
          rewritten_insns.push_back(static_cast<std::uint16_t>(bits >> 16U));
        };
        for (const auto i : layout_order) {
          const auto &instruction = decoded.instructions[i];
          if (instruction.kind == InstructionKind::Payload &&
              (rewritten_insns.size() & 1U) != 0U) {
            if (registers_size == 0U) {
              throw DexParseError(
                  DexErrorCode::InvalidClassData, old_offset,
                  "payload alignment requires at least one register");
            }
            // ART verifies unreachable alignment code with undefined
            // inputs, so the padding instruction must define v0.
            rewritten_insns.push_back(0x0012U); // const/4 v0, #0
          }
          if (rewritten_insns.size() != instruction_addresses[i]) {
            throw std::logic_error(
                "code relocation address map is inconsistent");
          }
          const auto replacement =
              prefix_spec.linear_replacements.find(instruction.offset);
          if (replacement != prefix_spec.linear_replacements.end()) {
            rewritten_insns.insert(rewritten_insns.end(),
                                   replacement->second.begin(),
                                   replacement->second.end());
            if (seal_unreachable_chain_after.at(i)) {
              rewritten_insns.insert(rewritten_insns.end(),
                                     {0x002aU, 0U, 0U});
            }
            continue;
          }
          if (instruction.kind == InstructionKind::Payload) {
            auto payload = instruction.code_units;
            if (payload.front() == 0x0100U || payload.front() == 0x0200U) {
              const auto source_it = payload_sources.find(instruction.offset);
              if (source_it == payload_sources.end()) {
                throw DexParseError(
                    DexErrorCode::InvalidClassData, old_offset,
                    "switch payload has no referring instruction");
              }
              const auto count = payload.at(1U);
              const auto targets_start =
                  payload.front() == 0x0100U ? 4U : 2U + count * 2U;
              for (std::uint32_t target_index = 0U; target_index < count;
                   ++target_index) {
                const auto at = targets_start + target_index * 2U;
                const auto old_relative =
                    signed32(payload.at(at), payload.at(at + 1U));
                const auto old_target64 =
                    static_cast<std::int64_t>(source_it->second) + old_relative;
                if (old_target64 < 0 || old_target64 > insns_size) {
                  throw DexParseError(
                      DexErrorCode::InvalidClassData, old_offset,
                      "switch case target is outside code item");
                }
                const auto relative =
                    static_cast<std::int64_t>(mapped_address(
                        static_cast<std::uint32_t>(old_target64))) -
                    instruction_address(source_it->second);
                if (relative < std::numeric_limits<std::int32_t>::min() ||
                    relative > std::numeric_limits<std::int32_t>::max()) {
                  throw std::length_error(
                      "switch case displacement exceeds int32");
                }
                const auto bits = static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(relative));
                payload.at(at) = static_cast<std::uint16_t>(bits);
                payload.at(at + 1U) = static_cast<std::uint16_t>(bits >> 16U);
              }
            }
            rewritten_insns.insert(rewritten_insns.end(), payload.begin(),
                                   payload.end());
            continue;
          }

          const auto new_offset = instruction_addresses[i];
          const auto branch_target = [&]() -> std::int64_t {
            if (instruction.targets.empty())
              return 0;
            return static_cast<std::int64_t>(
                       mapped_address(instruction.targets.front())) -
                   new_offset;
          };
          if (forms[i] == BranchForm::Goto16 ||
              forms[i] == BranchForm::Goto32 || instruction.opcode == 0x28U ||
              instruction.opcode == 0x29U || instruction.opcode == 0x2aU) {
            const auto displacement = branch_target();
            if (forms[i] == BranchForm::Goto32 || instruction.opcode == 0x2aU) {
              rewritten_insns.push_back(0x002aU);
              append_i32(displacement);
            } else if (forms[i] == BranchForm::Goto16 ||
                       instruction.opcode == 0x29U) {
              if (displacement < std::numeric_limits<std::int16_t>::min() ||
                  displacement > std::numeric_limits<std::int16_t>::max()) {
                throw std::length_error("goto/16 displacement exceeds int16");
              }
              rewritten_insns.push_back(0x0029U);
              rewritten_insns.push_back(static_cast<std::uint16_t>(
                  static_cast<std::int16_t>(displacement)));
            } else {
              if (displacement < std::numeric_limits<std::int8_t>::min() ||
                  displacement > std::numeric_limits<std::int8_t>::max()) {
                throw std::length_error("goto displacement exceeds int8");
              }
              rewritten_insns.push_back(static_cast<std::uint16_t>(
                  0x28U | (static_cast<std::uint16_t>(static_cast<std::uint8_t>(
                               static_cast<std::int8_t>(displacement)))
                           << 8U)));
            }
            continue;
          }
          if (forms[i] == BranchForm::LongIf) {
            static constexpr std::uint8_t inverse[] = {
                0x33U, 0x32U, 0x35U, 0x34U, 0x37U, 0x36U,
                0x39U, 0x38U, 0x3bU, 0x3aU, 0x3dU, 0x3cU,
            };
            const auto inverse_opcode = inverse[instruction.opcode - 0x32U];
            rewritten_insns.push_back(static_cast<std::uint16_t>(
                (instruction.code_units.front() & 0xff00U) | inverse_opcode));
            rewritten_insns.push_back(5U);
            rewritten_insns.push_back(0x002aU);
            append_i32(static_cast<std::int64_t>(
                           mapped_address(instruction.targets.front())) -
                       (new_offset + 2U));
            continue;
          }

          auto units = instruction.code_units;
          if (instruction.opcode >= 0x32U && instruction.opcode <= 0x3dU) {
            const auto displacement = branch_target();
            if (displacement < std::numeric_limits<std::int16_t>::min() ||
                displacement > std::numeric_limits<std::int16_t>::max()) {
              throw std::length_error(
                  "if displacement exceeds int16 after relaxation");
            }
            units.at(1U) = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(displacement));
          } else if (instruction.opcode == 0x2bU ||
                     instruction.opcode == 0x2cU ||
                     instruction.opcode == 0x26U) {
            const auto old_relative = signed32(units.at(1U), units.at(2U));
            const auto old_payload = static_cast<std::uint32_t>(
                static_cast<std::int64_t>(instruction.offset) + old_relative);
            const auto displacement =
                static_cast<std::int64_t>(mapped_address(old_payload)) -
                new_offset;
            if (displacement < std::numeric_limits<std::int32_t>::min() ||
                displacement > std::numeric_limits<std::int32_t>::max()) {
              throw std::length_error("payload displacement exceeds int32");
            }
            const auto bits = static_cast<std::uint32_t>(
                static_cast<std::int32_t>(displacement));
            units.at(1U) = static_cast<std::uint16_t>(bits);
            units.at(2U) = static_cast<std::uint16_t>(bits >> 16U);
          }
          if (instruction.opcode == 0x1aU) {
            const auto new_index = mapped_string(instruction.code_units.at(1U));
            if (promote_jumbo[i]) {
              units = {static_cast<std::uint16_t>(
                           (instruction.code_units.front() & 0xff00U) | 0x1bU),
                       static_cast<std::uint16_t>(new_index),
                       static_cast<std::uint16_t>(new_index >> 16U)};
            } else {
              units.at(1U) = static_cast<std::uint16_t>(new_index);
            }
          } else if (instruction.opcode == 0x1bU) {
            const auto old_index =
                static_cast<std::uint32_t>(instruction.code_units.at(1U)) |
                static_cast<std::uint32_t>(instruction.code_units.at(2U))
                    << 16U;
            const auto new_index = mapped_string(old_index);
            units.at(1U) = static_cast<std::uint16_t>(new_index);
            units.at(2U) = static_cast<std::uint16_t>(new_index >> 16U);
          } else if (instruction.opcode == 0x1cU ||
                     instruction.opcode == 0x1fU ||
                     instruction.opcode == 0x20U ||
                     instruction.opcode == 0x22U ||
                     instruction.opcode == 0x23U ||
                     instruction.opcode == 0x24U ||
                     instruction.opcode == 0x25U) {
            units.at(1U) = static_cast<std::uint16_t>(
                remap.types.at(instruction.code_units.at(1U)));
          } else if (instruction.opcode == 0xfaU ||
                     instruction.opcode == 0xfbU) {
            units.at(3U) = static_cast<std::uint16_t>(
                remap.protos.at(instruction.code_units.at(3U)));
          } else if (instruction.opcode == 0xffU) {
            units.at(1U) = static_cast<std::uint16_t>(
                remap.protos.at(instruction.code_units.at(1U)));
          }
          rewritten_insns.insert(rewritten_insns.end(), units.begin(),
                                 units.end());
          if (seal_unreachable_chain_after.at(i)) {
            rewritten_insns.insert(rewritten_insns.end(),
                                   {0x002aU, 0U, 0U});
          }
        }
        if (rewritten_insns.size() != address_map.back()) {
          throw std::logic_error(
              "rewritten code size disagrees with address map");
        }

        const auto replaces_body =
            prefix_spec.replacement_code_units.has_value();
        if (replaces_body) {
          rewritten_insns = *prefix_spec.replacement_code_units;
          if (rewritten_insns.empty()) {
            throw std::invalid_argument(
                "complete code replacement must not be empty");
          }
        }

        struct OutputTryRegion {
          std::uint32_t start{};
          std::uint32_t count{};
          std::vector<CodePrefix::CatchHandler> handlers;
        };
        std::vector<OutputTryRegion> output_tries;
        const auto &explicit_tries = replaces_body
                                         ? prefix_spec.replacement_try_regions
                                         : prefix_spec.try_regions;
        output_tries.reserve(explicit_tries.size() +
                             (replaces_body ? 0U : decoded.tries.size()));
        for (const auto &region : explicit_tries) {
          if (region.instruction_count == 0U ||
              region.start_address >= rewritten_insns.size() ||
              region.instruction_count >
                  rewritten_insns.size() - region.start_address ||
              region.handlers.empty()) {
            throw std::invalid_argument("invalid rewritten code try region");
          }
          for (const auto &handler : region.handlers) {
            if (handler.address >= rewritten_insns.size()) {
              throw std::invalid_argument(
                  "rewritten code catch handler is outside the method");
            }
            if (handler.type_idx.has_value() &&
                *handler.type_idx >= remap.types.size()) {
              throw std::invalid_argument(
                  "code prefix catch type index is invalid");
            }
          }
          output_tries.push_back({region.start_address,
                                  region.instruction_count, region.handlers});
        }
        if (!replaces_body)
          for (const auto &region : decoded.tries) {
            const auto new_start = mapped_address(region.start_address);
            const auto new_end =
                mapped_address(region.start_address + region.instruction_count);
            std::vector<CodePrefix::CatchHandler> handlers;
            handlers.reserve(region.handlers.size());
            for (const auto &handler : region.handlers) {
              handlers.push_back(
                  {handler.type_idx, mapped_address(handler.address)});
            }
            output_tries.push_back(
                {new_start, new_end - new_start, std::move(handlers)});
          }
        std::sort(output_tries.begin(), output_tries.end(),
                  [](const auto &left, const auto &right) {
                    return std::tie(left.start, left.count) <
                           std::tie(right.start, right.count);
                  });
        for (std::size_t i = 1U; i < output_tries.size(); ++i) {
          const auto previous_end =
              static_cast<std::uint64_t>(output_tries[i - 1U].start) +
              output_tries[i - 1U].count;
          if (previous_end > output_tries[i].start) {
            throw std::invalid_argument("relocated DEX try regions overlap");
          }
        }
        if (output_tries.size() > std::numeric_limits<std::uint16_t>::max()) {
          throw std::length_error("too many relocated DEX try regions");
        }

        // Consume the original variable-size catch handler list to find the
        // next code item.
        cursor = insns_end;
        if (tries_size != 0U) {
          const auto try_items_offset =
              insns_end + ((insns_size & 1U) != 0U ? 2U : 0U);
          const auto handler_list_offset =
              try_items_offset + static_cast<std::size_t>(tries_size) * 8U;
          if (handler_list_offset > source.size()) {
            throw DexParseError(
                DexErrorCode::Truncated, old_offset,
                "code_item try table truncated during relocation");
          }
          std::size_t old_handler_cursor = handler_list_offset;
          const auto handler_count = ReadUleb128(source, old_handler_cursor);
          old_handler_cursor += handler_count.size;
          for (std::uint32_t handler_index = 0U;
               handler_index < handler_count.value; ++handler_index) {
            const auto handler_size = ReadSleb128(source, old_handler_cursor);
            old_handler_cursor += handler_size.size;
            const auto typed_count =
                handler_size.value < 0
                    ? static_cast<std::uint32_t>(
                          -static_cast<std::int64_t>(handler_size.value))
                    : static_cast<std::uint32_t>(handler_size.value);
            for (std::uint32_t i = 0U; i < typed_count; ++i) {
              const auto type = ReadUleb128(source, old_handler_cursor);
              old_handler_cursor += type.size;
              const auto address = ReadUleb128(source, old_handler_cursor);
              old_handler_cursor += address.size;
            }
            if (handler_size.value <= 0) {
              const auto catch_all = ReadUleb128(source, old_handler_cursor);
              old_handler_cursor += catch_all.size;
            }
          }
          cursor = old_handler_cursor;
        }

        std::vector<std::uint8_t> bytes(result.begin() + old_offset,
                                        result.begin() + old_offset + 16U);
        if (prefix_spec.replacement_registers_size.has_value()) {
          if (*prefix_spec.replacement_registers_size < decoded.ins_size) {
            throw std::invalid_argument(
                "replacement registers_size is smaller than ins_size");
          }
          WriteU16(bytes, 0U, *prefix_spec.replacement_registers_size);
        }
        if (prefix_spec.replacement_outs_size.has_value()) {
          WriteU16(bytes, 4U, *prefix_spec.replacement_outs_size);
        }
        WriteU16(bytes, 6U, static_cast<std::uint16_t>(output_tries.size()));
        if (replaces_body)
          WriteU32(bytes, 8U, 0U);
        WriteU32(bytes, 12U,
                 static_cast<std::uint32_t>(rewritten_insns.size()));
        for (const auto unit : rewritten_insns) {
          bytes.push_back(static_cast<std::uint8_t>(unit));
          bytes.push_back(static_cast<std::uint8_t>(unit >> 8U));
        }
        if (!output_tries.empty()) {
          if ((rewritten_insns.size() & 1U) != 0U) {
            bytes.push_back(0U);
            bytes.push_back(0U);
          }
          const auto try_items_local = bytes.size();
          bytes.resize(bytes.size() + output_tries.size() * 8U, 0U);
          const auto handler_list_local = bytes.size();
          append_uleb(bytes, static_cast<std::uint32_t>(output_tries.size()));
          for (std::size_t try_index = 0U; try_index < output_tries.size();
               ++try_index) {
            const auto &region = output_tries[try_index];
            if (region.count == 0U || region.count > 0xffffU) {
              throw std::length_error(
                  "relocated try region exceeds uint16 code units");
            }
            const auto handler_relative = bytes.size() - handler_list_local;
            if (handler_relative > 0xffffU) {
              throw std::length_error(
                  "encoded catch handler offset exceeds uint16");
            }
            const auto try_offset = try_items_local + try_index * 8U;
            WriteU32(bytes, try_offset, region.start);
            WriteU16(bytes, try_offset + 4U,
                     static_cast<std::uint16_t>(region.count));
            WriteU16(bytes, try_offset + 6U,
                     static_cast<std::uint16_t>(handler_relative));
            std::size_t typed_count = 0U;
            bool has_catch_all = false;
            for (const auto &handler : region.handlers) {
              if (handler.type_idx.has_value())
                ++typed_count;
              else
                has_catch_all = true;
            }
            if (typed_count > static_cast<std::size_t>(
                                  std::numeric_limits<std::int32_t>::max())) {
              throw std::length_error("too many encoded catch handlers");
            }
            const auto encoded_count = EncodeSleb(
                has_catch_all ? -static_cast<std::int32_t>(typed_count)
                              : static_cast<std::int32_t>(typed_count));
            bytes.insert(bytes.end(), encoded_count.begin(),
                         encoded_count.end());
            for (const auto &handler : region.handlers) {
              if (!handler.type_idx.has_value())
                continue;
              append_uleb(bytes, remap.types.at(*handler.type_idx));
              append_uleb(bytes, handler.address);
            }
            if (has_catch_all) {
              const auto catch_all =
                  std::find_if(region.handlers.begin(), region.handlers.end(),
                               [](const auto &handler) {
                                 return !handler.type_idx.has_value();
                               });
              append_uleb(bytes, catch_all->address);
            }
          }
        }
        std::fill(result.begin() + old_offset, result.begin() + cursor, 0U);
        if ((old_debug_offset == 0U && addresses == nullptr) || replaces_body) {
          address_map = {};
        }
        code_items.push_back({old_offset, 0U,
                              replaces_body ? 0U : old_debug_offset,
                              std::move(address_map), std::move(bytes)});
      }
    }

    std::function<std::vector<std::uint8_t>(std::size_t&)> encode_annotation;
    std::function<std::vector<std::uint8_t>(std::size_t&)> encode_value;
    encode_annotation = [&](std::size_t& cursor) {
        std::vector<std::uint8_t> output;
        const auto old_type_index = read_uleb(cursor);
        if (old_type_index >= remap.types.size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                "annotation type index invalid");
        }
        append_uleb(output, remap.types[old_type_index]);
        const auto count = read_uleb(cursor);
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> elements;
        elements.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto old_name_index = read_uleb(cursor);
            if (old_name_index >= remap.strings.size()) {
                throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                    "annotation name index invalid");
            }
            elements.emplace_back(mapped_string(old_name_index), encode_value(cursor));
        }
        std::sort(elements.begin(), elements.end(), [](const auto& left, const auto& right) {
            return left.first < right.first;
        });
        for (std::size_t i = 1; i < elements.size(); ++i) {
            if (elements[i - 1U].first == elements[i].first) {
                throw std::runtime_error("annotation remap produced duplicate element names");
            }
        }
        append_uleb(output, count);
        for (const auto& [name_index, value] : elements) {
            append_uleb(output, name_index);
            output.insert(output.end(), value.begin(), value.end());
        }
        return output;
    };
    encode_value = [&](std::size_t& cursor) {
        if (cursor >= source.size()) {
            throw DexParseError(DexErrorCode::Truncated, cursor, "encoded_value header truncated");
        }
        const auto start = cursor;
        const auto value_header = source[cursor++];
        const auto value_type = static_cast<std::uint8_t>(value_header & 0x1fU);
        const auto width = static_cast<std::uint8_t>((value_header >> 5U) + 1U);
        std::vector<std::uint8_t> output;
        switch (value_type) {
            case 0x15U: {
                const auto old = read_fixed_index(cursor, width, remap.protos.size(), "method_type");
                append_index(output, value_type, remap.protos[old]);
                break;
            }
            case 0x16U: {
                const auto old = read_fixed_index(cursor, width, dex.method_handles().size(), "method_handle");
                append_index(output, value_type, old);
                break;
            }
            case 0x17U: {
                const auto old = read_fixed_index(cursor, width, remap.strings.size(), "string");
                append_index(output, value_type, mapped_string(old));
                break;
            }
            case 0x18U: {
                const auto old = read_fixed_index(cursor, width, remap.types.size(), "type");
                append_index(output, value_type, remap.types[old]);
                break;
            }
            case 0x19U:
            case 0x1bU: {
                const auto old = read_fixed_index(cursor, width, remap.fields.size(), "field");
                append_index(output, value_type, old, 4U);
                break;
            }
            case 0x1aU: {
                const auto old = read_fixed_index(cursor, width, remap.methods.size(), "method");
                append_index(output, value_type, old, 4U);
                break;
            }
            case 0x1cU: {
                output.push_back(0x1cU);
                const auto count = read_uleb(cursor);
                append_uleb(output, count);
                for (std::uint32_t i = 0; i < count; ++i) {
                    const auto value = encode_value(cursor);
                    output.insert(output.end(), value.begin(), value.end());
                }
                break;
            }
            case 0x1dU: {
                output.push_back(0x1dU);
                const auto annotation = encode_annotation(cursor);
                output.insert(output.end(), annotation.begin(), annotation.end());
                break;
            }
            case 0x1eU:
            case 0x1fU:
                output.push_back(value_header);
                break;
            default:
                if (cursor > source.size() || source.size() - cursor < width) {
                    throw DexParseError(DexErrorCode::Truncated, cursor,
                                        "encoded_value payload truncated during relocation");
                }
                output.insert(output.end(), source.begin() + start,
                              source.begin() + cursor + width);
                cursor += width;
                break;
        }
        return output;
    };

    struct VariableItem {
        std::uint32_t old_offset{};
        std::uint32_t new_offset{};
        std::vector<std::uint8_t> bytes;
    };
    std::vector<VariableItem> debug_items;
    std::vector<VariableItem> annotations;
    std::vector<VariableItem> arrays;
    std::map<std::uint32_t, std::vector<std::size_t>> static_value_classes;
    for (std::size_t class_index = 0; class_index < dex.classes().size(); ++class_index) {
        const auto offset = dex.classes()[class_index].static_values_off;
        if (offset == 0U) continue;
        static_value_classes[offset].push_back(class_index);
    }
    const auto default_static_value = [&](std::uint32_t field_idx) {
        const auto& field = dex.fields().at(field_idx);
        const auto descriptor = dex.descriptor(field.type_idx);
        if (descriptor.empty()) throw std::runtime_error("static field has an empty type descriptor");
        switch (descriptor.front()) {
            case 'Z': return std::vector<std::uint8_t>{0x1fU};
            case 'B': return std::vector<std::uint8_t>{0x00U, 0U};
            case 'S': return std::vector<std::uint8_t>{0x02U, 0U};
            case 'C': return std::vector<std::uint8_t>{0x03U, 0U};
            case 'I': return std::vector<std::uint8_t>{0x04U, 0U};
            case 'J': return std::vector<std::uint8_t>{0x06U, 0U};
            case 'F': return std::vector<std::uint8_t>{0x10U, 0U};
            case 'D': return std::vector<std::uint8_t>{0x11U, 0U};
            default: return std::vector<std::uint8_t>{0x1eU};
        }
    };
    std::map<std::size_t, std::size_t> static_array_item_indices;
    const auto append_ulebp1 = [&](std::vector<std::uint8_t>& output,
                                   std::uint32_t encoded,
                                   const std::vector<std::uint32_t>& index_remap,
                                   std::string_view label) {
        if (encoded == 0U) {
            append_uleb(output, 0U);
            return;
        }
        const auto old_index = encoded - 1U;
        if (old_index >= index_remap.size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, 0U,
                                std::string(label) + " debug index is invalid");
        }
        if (index_remap[old_index] == std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error(std::string(label) + " debug index overflows ulebp1");
        }
        append_uleb(output, index_remap[old_index] + 1U);
    };
    for (const auto& item : dex.map()) {
        if (item.type == 0x2003U) {
            std::size_t cursor = item.offset;
            for (std::uint32_t debug_index = 0; debug_index < item.size; ++debug_index) {
                const auto old_offset = static_cast<std::uint32_t>(cursor);
                const auto code_item = std::find_if(
                    code_items.begin(), code_items.end(), [&](const auto& candidate) {
                        return candidate.old_debug_offset == old_offset;
                    });
                const auto debug_address = [&](std::uint32_t old_address) {
                    if (code_item == code_items.end()) return old_address;
                    if (old_address >= code_item->address_map.size() ||
                        code_item->address_map[old_address] ==
                            std::numeric_limits<std::uint32_t>::max()) {
                        throw DexParseError(DexErrorCode::InvalidClassData, old_offset,
                                            "debug address is not an instruction boundary");
                    }
                    return code_item->address_map[old_address];
                };
                std::vector<std::uint8_t> bytes;
                append_uleb(bytes, read_uleb(cursor)); // line_start
                const auto parameters_size = read_uleb(cursor);
                append_uleb(bytes, parameters_size);
                for (std::uint32_t i = 0; i < parameters_size; ++i) {
                    append_ulebp1(bytes, read_uleb(cursor), reference_string_remap, "parameter name");
                }
                bool ended = false;
                std::uint32_t old_address = 0U;
                std::uint32_t new_address = 0U;
                while (!ended) {
                    if (cursor >= source.size()) {
                        throw DexParseError(DexErrorCode::Truncated, cursor,
                                            "debug_info opcode stream truncated");
                    }
                    const auto opcode = source[cursor++];
                    switch (opcode) {
                        case 0x00U:
                            bytes.push_back(opcode);
                            ended = true;
                            break;
                        case 0x01U: {
                            const auto old_delta = read_uleb(cursor);
                            if (old_delta > std::numeric_limits<std::uint32_t>::max() - old_address) {
                                throw DexParseError(DexErrorCode::IntegerOverflow, old_offset,
                                                    "debug address overflows uint32");
                            }
                            const auto next_old = old_address + old_delta;
                            const auto next_new = debug_address(next_old);
                            if (next_new < new_address) {
                                throw DexParseError(DexErrorCode::InvalidClassData, old_offset,
                                                    "debug address relocation is not monotonic");
                            }
                            bytes.push_back(opcode);
                            append_uleb(bytes, next_new - new_address);
                            old_address = next_old;
                            new_address = next_new;
                            break;
                        }
                        case 0x02U: {
                            bytes.push_back(opcode);
                            const auto value = ReadSleb128(source, cursor);
                            bytes.insert(bytes.end(), source.begin() + cursor,
                                         source.begin() + cursor + value.size);
                            cursor += value.size;
                            break;
                        }
                        case 0x03U:
                        case 0x04U:
                            bytes.push_back(opcode);
                            append_uleb(bytes, read_uleb(cursor));
                            append_ulebp1(bytes, read_uleb(cursor), reference_string_remap,
                                         "local name");
                            append_ulebp1(bytes, read_uleb(cursor), remap.types,
                                         "local type");
                            if (opcode == 0x04U) {
                                append_ulebp1(bytes, read_uleb(cursor), reference_string_remap,
                                             "local signature");
                            }
                            break;
                        case 0x05U:
                        case 0x06U:
                            bytes.push_back(opcode);
                            append_uleb(bytes, read_uleb(cursor));
                            break;
                        case 0x09U:
                            bytes.push_back(opcode);
                            append_ulebp1(bytes, read_uleb(cursor), reference_string_remap,
                                         "source file");
                            break;
                        default: {
                            if (opcode < 0x0aU) {
                                bytes.push_back(opcode); // prologue/epilogue marker
                                break;
                            }
                            constexpr std::uint32_t kLineRange = 15U;
                            const auto old_delta = static_cast<std::uint32_t>(
                                (opcode - 0x0aU) / kLineRange);
                            if (old_delta > std::numeric_limits<std::uint32_t>::max() - old_address) {
                                throw DexParseError(DexErrorCode::IntegerOverflow, old_offset,
                                                    "special debug address overflows uint32");
                            }
                            const auto next_old = old_address + old_delta;
                            const auto next_new = debug_address(next_old);
                            if (next_new < new_address || next_new - new_address < old_delta) {
                                throw DexParseError(DexErrorCode::InvalidClassData, old_offset,
                                                    "special debug relocation is not monotonic");
                            }
                            const auto extra = next_new - new_address - old_delta;
                            if (extra != 0U) {
                                bytes.push_back(0x01U); // DBG_ADVANCE_PC
                                append_uleb(bytes, extra);
                                new_address += extra;
                            }
                            bytes.push_back(opcode);
                            old_address = next_old;
                            new_address += old_delta;
                            break;
                        }
                    }
                }
                debug_items.push_back({old_offset, 0U, std::move(bytes)});
            }
            std::fill(result.begin() + item.offset, result.begin() + cursor, 0U);
        } else if (item.type == 0x2004U) {
            std::size_t cursor = item.offset;
            for (std::uint32_t annotation = 0; annotation < item.size; ++annotation) {
                const auto old_offset = static_cast<std::uint32_t>(cursor);
                if (cursor >= source.size()) {
                    throw DexParseError(DexErrorCode::Truncated, cursor, "annotation item truncated");
                }
                std::vector<std::uint8_t> bytes{source[cursor++]};
                const auto body = encode_annotation(cursor);
                bytes.insert(bytes.end(), body.begin(), body.end());
                annotations.push_back({old_offset, 0U, std::move(bytes)});
            }
            std::fill(result.begin() + item.offset, result.begin() + cursor, 0U);
        } else if (item.type == 0x2005U) {
            std::size_t cursor = item.offset;
            for (std::uint32_t array = 0; array < item.size; ++array) {
                const auto old_offset = static_cast<std::uint32_t>(cursor);
                const auto count = read_uleb(cursor);
                std::vector<std::vector<std::uint8_t>> values;
                values.reserve(count);
                for (std::uint32_t i = 0; i < count; ++i) {
                    values.push_back(encode_value(cursor));
                }
                std::vector<std::uint8_t> bytes;
                const auto static_class = static_value_classes.find(old_offset);
                append_uleb(bytes, count);
                for (const auto& value : values) {
                    bytes.insert(bytes.end(), value.begin(), value.end());
                }
                arrays.push_back({old_offset, 0U, std::move(bytes)});
                if (static_class != static_value_classes.end()) {
                    for (const auto class_index : static_class->second) {
                    const auto& static_fields = dex.class_data(class_index).static_fields;
                    if (count > static_fields.size()) {
                        throw std::runtime_error("static_values array exceeds static field count");
                    }
                    std::vector<std::pair<std::uint32_t, std::size_t>> order;
                    order.reserve(static_fields.size());
                    for (std::size_t old_position = 0; old_position < static_fields.size(); ++old_position) {
                        order.emplace_back(remap.fields.at(static_fields[old_position].field_idx),
                                           old_position);
                    }
                    std::sort(order.begin(), order.end());
                    std::vector<std::optional<std::vector<std::uint8_t>>> reordered(static_fields.size());
                    for (std::size_t new_position = 0; new_position < order.size(); ++new_position) {
                        const auto old_position = order[new_position].second;
                        if (old_position < values.size()) {
                            reordered[new_position] = values[old_position];
                        }
                    }
                    std::size_t output_count = 0U;
                    for (std::size_t i = 0; i < reordered.size(); ++i) {
                        if (reordered[i].has_value()) output_count = i + 1U;
                    }
                    std::vector<std::uint8_t> class_bytes;
                    append_uleb(class_bytes, static_cast<std::uint32_t>(output_count));
                    for (std::size_t new_position = 0; new_position < output_count; ++new_position) {
                        const auto& value = reordered[new_position].has_value() ?
                            *reordered[new_position] :
                            default_static_value(static_fields[order[new_position].second].field_idx);
                        class_bytes.insert(class_bytes.end(), value.begin(), value.end());
                    }
                    static_array_item_indices.emplace(class_index, arrays.size());
                    arrays.push_back({0U, 0U, std::move(class_bytes)});
                    }
                }
            }
            std::fill(result.begin() + item.offset, result.begin() + cursor, 0U);
        }
    }

    const auto old_map_end = static_cast<std::uint64_t>(header.map_off) + 4U +
                             static_cast<std::uint64_t>(dex.map().size()) * 12U;
    if (old_map_end != result.size()) {
        throw std::runtime_error("DEX map is not final; encoded-value relocation requires full rebuild");
    }
    result.resize(header.map_off);
    std::uint32_t code_section_off = 0U;
    for (auto& item : code_items) {
        while ((result.size() & 3U) != 0U) result.push_back(0U);
        if (code_section_off == 0U) code_section_off = static_cast<std::uint32_t>(result.size());
        item.new_offset = static_cast<std::uint32_t>(result.size());
        result.insert(result.end(), item.bytes.begin(), item.bytes.end());
    }
    std::uint32_t debug_section_off = 0U;
    for (auto& item : debug_items) {
        if (debug_section_off == 0U) debug_section_off = static_cast<std::uint32_t>(result.size());
        item.new_offset = static_cast<std::uint32_t>(result.size());
        result.insert(result.end(), item.bytes.begin(), item.bytes.end());
    }
    std::uint32_t annotation_section_off = 0U;
    for (auto& item : annotations) {
        if (annotation_section_off == 0U) annotation_section_off = static_cast<std::uint32_t>(result.size());
        item.new_offset = static_cast<std::uint32_t>(result.size());
        result.insert(result.end(), item.bytes.begin(), item.bytes.end());
    }
    std::uint32_t array_section_off = 0U;
    for (auto& item : arrays) {
        if (array_section_off == 0U) array_section_off = static_cast<std::uint32_t>(result.size());
        item.new_offset = static_cast<std::uint32_t>(result.size());
        result.insert(result.end(), item.bytes.begin(), item.bytes.end());
    }
    const auto relocated_offset = [](const auto& items, std::uint32_t old_offset,
                                     std::string_view label) {
        const auto found = std::find_if(items.begin(), items.end(), [&](const auto& item) {
            return item.old_offset == old_offset;
        });
        if (found == items.end()) {
            throw std::runtime_error(std::string(label) + " offset does not reference a mapped item");
        }
        return found->new_offset;
    };

    std::vector<VariableItem> class_data_items;
    std::uint32_t class_data_section_off = 0U;
    for (std::size_t class_index = 0; class_index < dex.classes().size(); ++class_index) {
        const auto old_offset = dex.classes()[class_index].class_data_off;
        if (old_offset == 0U) continue;
        const auto& data = dex.class_data(class_index);
        std::vector<std::uint8_t> bytes;
        append_uleb(bytes, static_cast<std::uint32_t>(data.static_fields.size()));
        append_uleb(bytes, static_cast<std::uint32_t>(data.instance_fields.size()));
        append_uleb(bytes, static_cast<std::uint32_t>(data.direct_methods.size()));
        append_uleb(bytes, static_cast<std::uint32_t>(data.virtual_methods.size()));
        const auto append_fields = [&](const auto& fields) {
            std::uint32_t previous = 0U;
            for (const auto& field : fields) {
                append_uleb(bytes, field.field_idx - previous);
                append_uleb(bytes, field.access_flags);
                previous = field.field_idx;
            }
        };
        const auto append_methods = [&](const auto& methods) {
            std::uint32_t previous = 0U;
            for (const auto& method : methods) {
                append_uleb(bytes, method.method_idx - previous);
                append_uleb(bytes, method.access_flags);
                append_uleb(bytes, method.code_off == 0U ? 0U :
                            relocated_offset(code_items, method.code_off, "code_item"));
                previous = method.method_idx;
            }
        };
        append_fields(data.static_fields);
        append_fields(data.instance_fields);
        append_methods(data.direct_methods);
        append_methods(data.virtual_methods);

        std::size_t old_cursor = old_offset;
        const auto static_count = read_uleb(old_cursor);
        const auto instance_count = read_uleb(old_cursor);
        const auto direct_count = read_uleb(old_cursor);
        const auto virtual_count = read_uleb(old_cursor);
        for (std::uint32_t i = 0; i < static_count; ++i) { (void)read_uleb(old_cursor); (void)read_uleb(old_cursor); }
        for (std::uint32_t i = 0; i < instance_count; ++i) { (void)read_uleb(old_cursor); (void)read_uleb(old_cursor); }
        for (std::uint32_t i = 0; i < direct_count; ++i) { (void)read_uleb(old_cursor); (void)read_uleb(old_cursor); (void)read_uleb(old_cursor); }
        for (std::uint32_t i = 0; i < virtual_count; ++i) { (void)read_uleb(old_cursor); (void)read_uleb(old_cursor); (void)read_uleb(old_cursor); }
        std::fill(result.begin() + old_offset, result.begin() + old_cursor, 0U);

        if (class_data_section_off == 0U) {
            class_data_section_off = static_cast<std::uint32_t>(result.size());
        }
        const auto new_offset = static_cast<std::uint32_t>(result.size());
        result.insert(result.end(), bytes.begin(), bytes.end());
        class_data_items.push_back({old_offset, new_offset, std::move(bytes)});
        WriteU32(result, static_cast<std::size_t>(header.class_defs_off) +
                           class_index * 32U + 24U, new_offset);
    }

    for (const auto& map_item : dex.map()) {
        if (map_item.type != 0x1003U) continue;
        std::size_t cursor = map_item.offset;
        for (std::uint32_t set = 0; set < map_item.size; ++set) {
            const auto count = ReadU32(source, cursor);
            cursor += 4U;
            const auto entries_offset = cursor;
            std::vector<std::pair<std::uint32_t, std::uint32_t>> entries;
            entries.reserve(count);
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto old_offset = ReadU32(source, cursor);
                const auto found = std::find_if(annotations.begin(), annotations.end(),
                                                [&](const auto& item) {
                    return item.old_offset == old_offset;
                });
                if (found == annotations.end()) {
                    throw std::runtime_error("annotation_set offset does not reference a mapped annotation");
                }
                const auto type = ReadUleb128(
                    std::span<const std::uint8_t>(found->bytes.data(), found->bytes.size()), 1U);
                entries.emplace_back(type.value, found->new_offset);
                cursor += 4U;
            }
            std::sort(entries.begin(), entries.end());
            for (std::size_t i = 1; i < entries.size(); ++i) {
                if (entries[i - 1U].first == entries[i].first) {
                    throw std::runtime_error("annotation_set has duplicate remapped annotation types");
                }
            }
            for (std::size_t i = 0; i < entries.size(); ++i) {
                WriteU32(result, entries_offset + i * 4U, entries[i].second);
            }
        }
    }
    for (std::size_t class_index = 0; class_index < dex.classes().size(); ++class_index) {
        const auto offset = static_cast<std::size_t>(header.class_defs_off) + class_index * 32U + 28U;
        const auto old_array = ReadU32(result, offset);
        if (old_array != 0U) {
            const auto relocated = static_array_item_indices.find(class_index);
            if (relocated == static_array_item_indices.end()) {
                throw std::runtime_error("class static_values array was not relocated");
            }
            WriteU32(result, offset, arrays.at(relocated->second).new_offset);
        }
    }
    for (const auto& call_site : dex.call_sites()) {
        WriteU32(result, call_site.item_offset,
                 relocated_offset(arrays, call_site.encoded_array_off, "call_site"));
    }
    for (const auto& code_item : code_items) {
        if (code_item.old_debug_offset != 0U) {
            WriteU32(result, code_item.new_offset + 8U,
                     relocated_offset(debug_items, code_item.old_debug_offset, "debug_info"));
        }
    }

    while ((result.size() & 3U) != 0U) result.push_back(0U);
    const auto new_map_off = static_cast<std::uint32_t>(result.size());
    auto map_copy = dex.map();
    for (auto& item : map_copy) {
        if (item.type == 0x1000U) item.offset = new_map_off;
        if (item.type == 0x2000U) {
            item.offset = class_data_section_off;
            item.size = static_cast<std::uint32_t>(class_data_items.size());
        }
        if (item.type == 0x2001U) {
            item.offset = code_section_off;
            item.size = static_cast<std::uint32_t>(code_items.size());
        }
        if (item.type == 0x2003U) item.offset = debug_section_off;
        if (item.type == 0x2004U) item.offset = annotation_section_off;
        if (item.type == 0x2005U) {
            item.offset = array_section_off;
            item.size = static_cast<std::uint32_t>(arrays.size());
        }
    }
    std::sort(map_copy.begin(), map_copy.end(), [](const auto& left, const auto& right) {
        return std::tie(left.offset, left.type) < std::tie(right.offset, right.type);
    });
    const auto append_u16 = [&](std::uint16_t value) {
        result.push_back(static_cast<std::uint8_t>(value));
        result.push_back(static_cast<std::uint8_t>(value >> 8U));
    };
    const auto append_u32 = [&](std::uint32_t value) {
        for (unsigned shift = 0U; shift < 32U; shift += 8U) {
            result.push_back(static_cast<std::uint8_t>(value >> shift));
        }
    };
    append_u32(static_cast<std::uint32_t>(map_copy.size()));
    for (const auto& item : map_copy) {
        append_u16(item.type); append_u16(0U); append_u32(item.size); append_u32(item.offset);
    }
    WriteU32(result, 0x34U, new_map_off);
    WriteU32(result, 0x20U, static_cast<std::uint32_t>(result.size()));
    WriteU32(result, 0x68U, static_cast<std::uint32_t>(result.size()) - header.data_off);
    if (dex.version() == 41U) {
        WriteU32(result, 0x70U, static_cast<std::uint32_t>(result.size()));
    }
    UpdateDexChecksums(result);
    if (addresses != nullptr) {
        CodeAddressMaps mapped;
        std::map<std::uint32_t, const CodeItemRelocation*> by_offset;
        for (const auto& item : code_items) by_offset.emplace(item.old_offset, &item);
        for (std::size_t c = 0; c < dex.classes().size(); ++c) {
            const auto& data = dex.class_data(c);
            for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
                for (const auto& method : *methods) {
                    if (!method.code_off) continue;
                    const auto& map = by_offset.at(method.code_off)->address_map;
                    if (map.empty()) continue; // complete replacement has no correspondence
                    auto& boundaries = mapped[dex.method_key(method.method_idx)];
                    for (const auto& ins : DecodeCodeItem(dex, method.code_off).instructions)
                        boundaries.emplace(ins.offset, map.at(ins.offset));
                    boundaries.emplace(static_cast<std::uint32_t>(map.size() - 1U), map.back());
                }
            }
        }
        *addresses = std::move(mapped);
    }
    return result;
}

template <typename Key>
std::vector<std::uint32_t> SortedMap(std::size_t count, const std::vector<Key>& keys) {
    std::vector<std::uint32_t> order(count);
    for (std::size_t i = 0; i < count; ++i) order[i] = static_cast<std::uint32_t>(i);
    std::sort(order.begin(), order.end(), [&](auto left, auto right) { return keys[left] < keys[right]; });
    std::vector<std::uint32_t> remap(count);
    for (std::size_t new_index = 0; new_index < order.size(); ++new_index) remap[order[new_index]] = static_cast<std::uint32_t>(new_index);
    return remap;
}

} // namespace

IdRemap BuildCanonicalRemap(const DexFile& dex, const RemapOptions& options,
                            const std::vector<std::uint32_t>& string_aliases) {
    IdRemap result;
    if (!string_aliases.empty()) {
        if (string_aliases.size() != dex.strings().size()) {
            throw std::invalid_argument("string alias size mismatch");
        }
        for (const auto representative : string_aliases) {
            if (representative >= string_aliases.size()) {
                throw std::invalid_argument("string alias representative is invalid");
            }
        }
        result.string_aliases = string_aliases;
    }
    result.strings = Identity(dex.strings().size());
    if (options.sort_strings) {
        std::vector<std::vector<std::uint16_t>> keys; keys.reserve(dex.strings().size());
        for (const auto& value : dex.strings()) keys.push_back(Mutf8Key(value.mutf8));
        result.strings = SortedMap(keys.size(), keys);
    }
    result.types = Identity(dex.types().size());
    if (options.sort_types) {
        std::vector<std::tuple<std::uint32_t>> keys;
        for (const auto& type : dex.types()) keys.emplace_back(result.strings[type.descriptor_idx]);
        result.types = SortedMap(keys.size(), keys);
    }
    result.protos = Identity(dex.protos().size());
    if (options.sort_protos) {
        std::vector<std::tuple<std::uint32_t, std::vector<std::uint32_t>>> keys;
        for (const auto& proto : dex.protos()) {
            std::vector<std::uint32_t> parameters;
            for (const auto type_idx : dex.type_list(proto.parameters_off)) {
                parameters.push_back(result.types[type_idx]);
            }
            keys.emplace_back(result.types[proto.return_type_idx], std::move(parameters));
        }
        result.protos = SortedMap(keys.size(), keys);
    }
    result.fields = Identity(dex.fields().size());
    if (options.sort_fields) {
        std::vector<std::tuple<std::uint16_t, std::uint32_t, std::uint16_t>> keys;
        for (const auto& field : dex.fields()) {
            const auto name_idx = result.string_aliases.empty() ? field.name_idx :
                                  result.string_aliases[field.name_idx];
            keys.emplace_back(static_cast<std::uint16_t>(result.types[field.class_idx]), result.strings[name_idx], static_cast<std::uint16_t>(result.types[field.type_idx]));
        }
        result.fields = SortedMap(keys.size(), keys);
    }
    result.methods = Identity(dex.methods().size());
    if (options.sort_methods) {
        std::vector<std::tuple<std::uint16_t, std::uint32_t, std::uint16_t>> keys;
        for (const auto& method : dex.methods()) {
            const auto name_idx = result.string_aliases.empty() ? method.name_idx :
                                  result.string_aliases[method.name_idx];
            keys.emplace_back(static_cast<std::uint16_t>(result.types[method.class_idx]), result.strings[name_idx], static_cast<std::uint16_t>(result.protos[method.proto_idx]));
        }
        result.methods = SortedMap(keys.size(), keys);
    }
    return result;
}

std::vector<std::uint32_t> ConstrainRemapToEncodedWidth(
    const std::vector<std::uint32_t>& desired_remap) {
    std::vector<std::uint32_t> result(desired_remap.size(), 0U);
    constexpr std::uint64_t bounds[] = {0U, 0x100U, 0x10000U, 0x1000000U, 0x100000000ULL};
    for (std::size_t bucket = 0; bucket + 1U < std::size(bounds); ++bucket) {
        const auto begin = static_cast<std::size_t>(std::min<std::uint64_t>(bounds[bucket], desired_remap.size()));
        const auto end = static_cast<std::size_t>(std::min<std::uint64_t>(bounds[bucket + 1U], desired_remap.size()));
        std::vector<std::uint32_t> old_indices;
        for (std::size_t old = begin; old < end; ++old) old_indices.push_back(static_cast<std::uint32_t>(old));
        std::sort(old_indices.begin(), old_indices.end(), [&](auto left, auto right) { return desired_remap[left] < desired_remap[right]; });
        for (std::size_t position = 0; position < old_indices.size(); ++position) result[old_indices[position]] = static_cast<std::uint32_t>(begin + position);
    }
    return result;
}

std::vector<std::uint8_t> ApplyIdRemap(const DexFile& dex, const IdRemap& remap) {
    if (remap.strings.size() != dex.strings().size() || remap.types.size() != dex.types().size() ||
        remap.protos.size() != dex.protos().size() || remap.fields.size() != dex.fields().size() ||
        remap.methods.size() != dex.methods().size()) throw std::invalid_argument("ID remap size mismatch");
    if (!remap.string_aliases.empty()) {
        if (remap.string_aliases.size() != dex.strings().size()) {
            throw std::invalid_argument("string alias size mismatch");
        }
        for (const auto representative : remap.string_aliases) {
            if (representative >= remap.string_aliases.size()) {
                throw std::invalid_argument("string alias representative is invalid");
            }
        }
    }
    (void)InversePermutation(remap.fields, "field");
    (void)InversePermutation(remap.methods, "method");
    const auto aliases_identity = remap.string_aliases.empty() ||
                                  IsIdentity(remap.string_aliases);
    if (IsIdentity(remap.strings) && IsIdentity(remap.types) &&
        IsIdentity(remap.protos) && IsIdentity(remap.fields) &&
        IsIdentity(remap.methods) && aliases_identity) {
        return std::vector<std::uint8_t>(dex.bytes().begin(), dex.bytes().end());
    }
    if (dex.header().header_offset != 0U ||
        dex.header().container_size != dex.bytes().size() ||
        dex.header().file_size != dex.bytes().size()) {
        throw std::runtime_error(
            "ID remap of a shared/multi-header DEX 041 container requires container writer");
    }
    auto rewritten = RewritePrimaryIds(dex, remap);
    if (!IsIdentity(remap.fields) || !IsIdentity(remap.methods)) {
        const auto primary = DexFile::Parse(rewritten);
        rewritten = primary.RewriteMemberIndicesRelocated(remap.fields, remap.methods);
    }
    const auto output = DexFile::Parse(rewritten);
    std::string canonical_issue;
    if (!output.VerifyCanonicalOrder(&canonical_issue)) {
        throw std::runtime_error("ID remap output is not in canonical DEX order: " +
                                 canonical_issue);
    }
    return rewritten;
}

std::vector<std::uint8_t> RewriteCodePrefixes(const DexFile& dex,
                                              const std::vector<CodePrefix>& prefixes,
                                              CodeAddressMaps* addresses) {
    if (dex.header().header_offset != 0U ||
        dex.header().container_size != dex.bytes().size() ||
        dex.header().file_size != dex.bytes().size()) {
        throw std::runtime_error(
            "code rewrite of a shared/multi-header DEX 041 container requires container writer");
    }
    std::set<std::uint32_t> existing;
    for (std::size_t class_index = 0U; class_index < dex.classes().size(); ++class_index) {
        const auto& data = dex.class_data(class_index);
        for (const auto* group : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *group) {
                if (method.code_off != 0U) existing.insert(method.code_off);
            }
        }
    }
    std::map<std::uint32_t, CodePrefix> by_offset;
    for (const auto& prefix : prefixes) {
        if (prefix.code_units.empty() && !prefix.reorder_blocks &&
            prefix.linear_replacements.empty() &&
            !prefix.replacement_code_units.has_value()) {
            continue;
        }
        if (!existing.contains(prefix.code_off)) {
            throw std::invalid_argument("code prefix offset does not reference a method body");
        }
        if (!by_offset.emplace(prefix.code_off, prefix).second) {
            throw std::invalid_argument("duplicate code prefix method offset");
        }
    }
    if (by_offset.empty()) {
        if (addresses != nullptr) {
            CodeAddressMaps identity;
            for (std::size_t c = 0; c < dex.classes().size(); ++c) {
                const auto& data = dex.class_data(c);
                for (const auto* methods : {&data.direct_methods, &data.virtual_methods})
                    for (const auto& method : *methods) {
                        if (!method.code_off) continue;
                        const auto code = DecodeCodeItem(dex, method.code_off);
                        auto& map = identity[dex.method_key(method.method_idx)];
                        for (const auto& ins : code.instructions) map.emplace(ins.offset, ins.offset);
                        map.emplace(static_cast<std::uint32_t>(code.insns.size()), static_cast<std::uint32_t>(code.insns.size()));
                    }
            }
            *addresses = std::move(identity);
        }
        return dex.Write();
    }
    IdRemap identity;
    identity.strings = Identity(dex.strings().size());
    identity.types = Identity(dex.types().size());
    identity.protos = Identity(dex.protos().size());
    identity.fields = Identity(dex.fields().size());
    identity.methods = Identity(dex.methods().size());
    CodeAddressMaps mapped;
    auto output = RewritePrimaryIds(dex, identity, &by_offset, addresses != nullptr ? &mapped : nullptr);
    const auto parsed = DexFile::Parse(output);
    const auto verification = VerifyDex(parsed, VerificationLevel::Full);
    if (!verification.ok) {
        throw std::runtime_error(verification.issues.empty() ?
            "code prefix rewrite verification failed" : verification.issues.front().message);
    }
    if (addresses != nullptr) *addresses = std::move(mapped);
    return output;
}

} // namespace birch::dex
