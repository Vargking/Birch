#include "birch/dex/partition.h"

#include "birch/dex/code.h"
#include "birch/dex/leb128.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <tuple>

namespace birch::dex {
namespace {

constexpr std::uint32_t kMax16BitIds = 65535U;

template <typename Set>
void MergeSet(Set& destination, const Set& source) {
    destination.insert(source.begin(), source.end());
}

std::uint32_t ReadReference(const DecodedInstruction& instruction,
                            std::size_t low_word, bool wide = false) {
    if (low_word >= instruction.code_units.size() ||
        (wide && low_word + 1U >= instruction.code_units.size())) {
        throw std::logic_error("decoded instruction is missing a reference operand");
    }
    auto value = static_cast<std::uint32_t>(instruction.code_units[low_word]);
    if (wide) {
        value |= static_cast<std::uint32_t>(instruction.code_units[low_word + 1U]) << 16U;
    }
    return value;
}

void AddType(const DexFile& dex, std::uint32_t index, ClassFootprint& output) {
    const auto value = dex.descriptor(index);
    output.types.insert(value);
    output.strings.insert(value);
}

void AddProto(const DexFile& dex, std::uint32_t index, ClassFootprint& output) {
    if (index >= dex.protos().size()) {
        throw DexParseError(DexErrorCode::InvalidIndex, 0, "proto reference is invalid");
    }
    const auto& proto = dex.protos()[index];
    output.protos.insert(dex.proto_key(index));
    output.strings.insert(dex.string(proto.shorty_idx));
    AddType(dex, proto.return_type_idx, output);
    for (const auto parameter : dex.type_list(proto.parameters_off)) {
        AddType(dex, parameter, output);
    }
}

void AddField(const DexFile& dex, std::uint32_t index, ClassFootprint& output) {
    if (index >= dex.fields().size()) {
        throw DexParseError(DexErrorCode::InvalidIndex, 0, "field reference is invalid");
    }
    const auto& field = dex.fields()[index];
    output.fields.insert(dex.field_key(index));
    output.strings.insert(dex.string(field.name_idx));
    AddType(dex, field.class_idx, output);
    AddType(dex, field.type_idx, output);
}

void AddMethod(const DexFile& dex, std::uint32_t index, ClassFootprint& output) {
    if (index >= dex.methods().size()) {
        throw DexParseError(DexErrorCode::InvalidIndex, 0, "method reference is invalid");
    }
    const auto& method = dex.methods()[index];
    output.methods.insert(dex.method_key(index));
    output.strings.insert(dex.string(method.name_idx));
    AddType(dex, method.class_idx, output);
    AddProto(dex, method.proto_idx, output);
}

void AddInstructionReferences(const DexProgram& program, std::size_t dex_index,
                              const DexFile& dex, const CodeItem& code,
                              ClassFootprint& output) {
    for (const auto& instruction : code.instructions) {
        const auto opcode = instruction.opcode;
        if (opcode == 0x1aU) {
            const auto index = ReadReference(instruction, 1U);
            output.strings.insert(dex.string(index));
        } else if (opcode == 0x1bU) {
            const auto index = ReadReference(instruction, 1U, true);
            output.strings.insert(dex.string(index));
        } else if (opcode == 0x1cU || opcode == 0x1fU || opcode == 0x20U ||
                   opcode == 0x22U || opcode == 0x23U || opcode == 0x24U ||
                   opcode == 0x25U) {
            AddType(dex, ReadReference(instruction, 1U), output);
        } else if (opcode >= 0x52U && opcode <= 0x6dU) {
            AddField(dex, ReadReference(instruction, 1U), output);
        } else if ((opcode >= 0x6eU && opcode <= 0x72U) ||
                   (opcode >= 0x74U && opcode <= 0x78U)) {
            AddMethod(dex, ReadReference(instruction, 1U), output);
        } else if (opcode == 0xfaU || opcode == 0xfbU) {
            AddMethod(dex, ReadReference(instruction, 1U), output);
            AddProto(dex, ReadReference(instruction, 3U), output);
        } else if (opcode == 0xfcU || opcode == 0xfdU) {
            output.call_sites.insert(std::string(program.dex_name(dex_index)) + "#callsite:" +
                                     std::to_string(ReadReference(instruction, 1U)));
        } else if (opcode == 0xfeU) {
            output.method_handles.insert(std::string(program.dex_name(dex_index)) + "#handle:" +
                                         std::to_string(ReadReference(instruction, 1U)));
        } else if (opcode == 0xffU) {
            AddProto(dex, ReadReference(instruction, 1U), output);
        }
    }
    for (const auto& region : code.tries) {
        for (const auto& handler : region.handlers) {
            if (handler.type_idx.has_value()) {
                AddType(dex, *handler.type_idx, output);
            }
        }
    }
}

std::size_t Weight(const ClassFootprint& footprint) {
    return footprint.strings.size() + footprint.types.size() + footprint.protos.size() +
           footprint.fields.size() + footprint.methods.size() + footprint.call_sites.size() +
           footprint.method_handles.size();
}

} // namespace

void MergeClassFootprint(ClassFootprint& destination,
                         const ClassFootprint& source) {
    MergeSet(destination.strings, source.strings);
    MergeSet(destination.types, source.types);
    MergeSet(destination.protos, source.protos);
    MergeSet(destination.fields, source.fields);
    MergeSet(destination.methods, source.methods);
    MergeSet(destination.call_sites, source.call_sites);
    MergeSet(destination.method_handles, source.method_handles);
}

bool ClassFootprintFits(const ClassFootprint& current,
                        const ClassFootprint& addition,
                        const IdLimits& limits) {
    const auto union_size = [](const auto& left, const auto& right) {
        std::size_t count = left.size();
        for (const auto& value : right) {
            count += left.contains(value) ? 0U : 1U;
        }
        return count;
    };
    return union_size(current.strings, addition.strings) <= limits.strings &&
           union_size(current.types, addition.types) <= limits.types &&
           union_size(current.protos, addition.protos) <= limits.protos &&
           union_size(current.fields, addition.fields) <= limits.fields &&
           union_size(current.methods, addition.methods) <= limits.methods &&
           union_size(current.call_sites, addition.call_sites) <= limits.call_sites &&
           union_size(current.method_handles, addition.method_handles) <=
               limits.method_handles;
}

void IdLimits::Validate() const {
    if (strings == 0U || types == 0U || protos == 0U || fields == 0U || methods == 0U ||
        call_sites == 0U || method_handles == 0U) {
        throw std::invalid_argument("DEX ID limits must be greater than zero");
    }
    if (types > kMax16BitIds || protos > kMax16BitIds || fields > kMax16BitIds ||
        methods > kMax16BitIds || call_sites > kMax16BitIds ||
        method_handles > kMax16BitIds) {
        throw std::invalid_argument("configured DEX ID limit exceeds the format hard limit");
    }
}

ClassFootprint CollectClassFootprint(const DexProgram& program, ClassHandle handle) {
    const auto& dex = program.dex(handle.dex_index);
    if (handle.class_index >= dex.classes().size()) {
        throw std::out_of_range("class handle is invalid");
    }
    const auto& definition = dex.classes()[handle.class_index];
    ClassFootprint output;
    AddType(dex, definition.class_idx, output);
    if (definition.superclass_idx != std::numeric_limits<std::uint32_t>::max()) {
        AddType(dex, definition.superclass_idx, output);
    }
    for (const auto interface_type : dex.type_list(definition.interfaces_off)) {
        AddType(dex, interface_type, output);
    }
    if (definition.source_file_idx != std::numeric_limits<std::uint32_t>::max()) {
        output.strings.insert(dex.string(definition.source_file_idx));
    }
    const auto& data = dex.class_data(handle.class_index);
    const auto add_fields = [&](const auto& fields) {
        for (const auto& field : fields) {
            AddField(dex, field.field_idx, output);
        }
    };
    const auto add_methods = [&](const auto& methods) {
        for (const auto& method : methods) {
            AddMethod(dex, method.method_idx, output);
            if (method.code_off != 0U) {
                AddInstructionReferences(program, handle.dex_index, dex,
                                         DecodeCodeItem(dex, method.code_off), output);
            }
        }
    };
    add_fields(data.static_fields);
    add_fields(data.instance_fields);
    add_methods(data.direct_methods);
    add_methods(data.virtual_methods);
    return output;
}

std::vector<DexPartition> PartitionProgram(const DexProgram& program,
                                           const PartitionOptions& options) {
    options.limits.Validate();
    struct Candidate {
        ClassHandle handle;
        std::string descriptor;
        ClassFootprint footprint;
        bool primary{};
    };
    std::vector<Candidate> candidates;
    for (const auto handle : program.classes()) {
        auto descriptor = program.class_descriptor(handle);
        candidates.push_back({handle, descriptor, CollectClassFootprint(program, handle),
                              options.primary_dex_classes.contains(descriptor)});
    }
    if (!options.preserve_input_order) {
        std::stable_sort(candidates.begin(), candidates.end(), [](const auto& left, const auto& right) {
            if (left.primary != right.primary) {
                return left.primary > right.primary;
            }
            return Weight(left.footprint) > Weight(right.footprint);
        });
    }

    std::vector<DexPartition> result(1);
    const auto add = [&](DexPartition& partition, const Candidate& candidate) {
        if (!ClassFootprintFits(partition.footprint, candidate.footprint,
                                options.limits)) {
            return false;
        }
        partition.classes.push_back(candidate.handle);
        MergeClassFootprint(partition.footprint, candidate.footprint);
        return true;
    };
    for (const auto& candidate : candidates) {
        if (!candidate.primary) {
            continue;
        }
        if (!add(result.front(), candidate)) {
            throw std::runtime_error("primary DEX classes exceed configured ID limits at " +
                                     candidate.descriptor);
        }
    }
    for (const auto& candidate : candidates) {
        if (candidate.primary) {
            continue;
        }
        if (!ClassFootprintFits({}, candidate.footprint, options.limits)) {
            throw std::runtime_error("class footprint exceeds configured DEX ID limits: " +
                                     candidate.descriptor);
        }
        bool placed = false;
        if (options.preserve_input_order) {
            placed = add(result.back(), candidate);
        } else {
            for (auto& partition : result) {
                if (add(partition, candidate)) {
                    placed = true;
                    break;
                }
            }
        }
        if (!placed) {
            result.emplace_back();
            if (!add(result.back(), candidate)) {
                throw std::logic_error("failed to add class to an empty DEX partition");
            }
        }
    }
    if (result.size() == 1U && result.front().classes.empty()) {
        result.clear();
    }
    return result;
}

} // namespace birch::dex
