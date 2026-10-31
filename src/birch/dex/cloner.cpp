#include "birch/dex/cloner.h"

#include "birch/dex/code.h"
#include "birch/dex/leb128.h"
#include "birch/dex/verifier.h"

#include <algorithm>
#include <bit>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace birch::dex {
namespace {

constexpr std::uint32_t kNoIndex = 0xffffffffU;

class Reader final {
public:
    explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    [[nodiscard]] std::uint8_t U8(std::size_t offset) const {
        Check(offset, 1U);
        return bytes_[offset];
    }

    [[nodiscard]] std::uint16_t U16(std::size_t offset) const {
        Check(offset, 2U);
        return static_cast<std::uint16_t>(bytes_[offset]) |
               static_cast<std::uint16_t>(bytes_[offset + 1U]) << 8U;
    }

    [[nodiscard]] std::uint32_t U32(std::size_t offset) const {
        Check(offset, 4U);
        return static_cast<std::uint32_t>(bytes_[offset]) |
               static_cast<std::uint32_t>(bytes_[offset + 1U]) << 8U |
               static_cast<std::uint32_t>(bytes_[offset + 2U]) << 16U |
               static_cast<std::uint32_t>(bytes_[offset + 3U]) << 24U;
    }

    [[nodiscard]] std::uint64_t Unsigned(std::size_t& cursor,
                                         std::uint8_t width) const {
        if (width == 0U || width > 8U) {
            throw DexParseError(DexErrorCode::InvalidClassData, cursor,
                                "invalid encoded value width");
        }
        Check(cursor, width);
        std::uint64_t value = 0U;
        for (std::uint8_t i = 0U; i < width; ++i) {
            value |= static_cast<std::uint64_t>(bytes_[cursor + i]) << (i * 8U);
        }
        cursor += width;
        return value;
    }

    [[nodiscard]] std::uint32_t Uleb(std::size_t& cursor) const {
        try {
            const auto value = ReadUleb128(bytes_, cursor);
            cursor += value.size;
            return value.value;
        } catch (const std::runtime_error& error) {
            throw DexParseError(DexErrorCode::InvalidClassData, cursor, error.what());
        }
    }

    [[nodiscard]] std::int32_t Sleb(std::size_t& cursor) const {
        try {
            const auto value = ReadSleb128(bytes_, cursor);
            cursor += value.size;
            return value.value;
        } catch (const std::runtime_error& error) {
            throw DexParseError(DexErrorCode::InvalidClassData, cursor, error.what());
        }
    }

private:
    void Check(std::size_t offset, std::size_t size) const {
        if (offset > bytes_.size() || size > bytes_.size() - offset) {
            throw DexParseError(DexErrorCode::Truncated, offset,
                                "DEX structure is truncated during class cloning");
        }
    }

    std::span<const std::uint8_t> bytes_;
};

std::uint32_t InstructionReference(const DecodedInstruction& instruction,
                                   std::size_t word, bool wide = false) {
    if (word >= instruction.code_units.size() ||
        (wide && word + 1U >= instruction.code_units.size())) {
        throw DexParseError(DexErrorCode::InvalidClassData, instruction.offset,
                            "instruction reference operand is truncated");
    }
    auto value = static_cast<std::uint32_t>(instruction.code_units[word]);
    if (wide) {
        value |= static_cast<std::uint32_t>(instruction.code_units[word + 1U]) << 16U;
    }
    return value;
}

std::int64_t SignExtend(std::uint64_t value, std::uint8_t width) {
    const auto bits = static_cast<unsigned>(width) * 8U;
    if (bits < 64U && (value & (std::uint64_t{1U} << (bits - 1U))) != 0U) {
        value |= ~std::uint64_t{0U} << bits;
    }
    return static_cast<std::int64_t>(value);
}

std::string ProtoKey(const ProtoReference& proto) {
    std::string key{"("};
    for (const auto& parameter : proto.parameter_types) key += parameter;
    key += ')';
    key += proto.return_type;
    return key;
}

std::string FieldKey(const FieldReference& field) {
    return field.owner + "->" + field.name + ':' + field.type;
}

std::string MethodKey(const MethodReference& method) {
    return method.owner + "->" + method.name +
           ProtoKey({method.return_type, method.parameter_types});
}

char ShortType(std::string_view descriptor) {
    if (descriptor.empty()) {
        throw std::invalid_argument("empty type descriptor in class footprint");
    }
    return descriptor.front() == 'L' || descriptor.front() == '[' ?
        'L' : descriptor.front();
}

ClassFootprint CollectSpecFootprint(const ClassSpec& klass) {
    ClassFootprint result;
    const auto add_string = [&](const std::string& value) {
        result.strings.insert(value);
    };
    const auto add_type = [&](const std::string& descriptor) {
        result.types.insert(descriptor);
        add_string(descriptor);
    };
    const auto add_proto = [&](const ProtoReference& proto) {
        result.protos.insert(ProtoKey(proto));
        add_type(proto.return_type);
        std::string shorty(1U, ShortType(proto.return_type));
        for (const auto& parameter : proto.parameter_types) {
            add_type(parameter);
            shorty.push_back(ShortType(parameter));
        }
        add_string(shorty);
    };
    const auto add_field = [&](const FieldReference& field) {
        result.fields.insert(FieldKey(field));
        add_type(field.owner);
        add_type(field.type);
        add_string(field.name);
    };
    const auto add_method = [&](const MethodReference& method) {
        result.methods.insert(MethodKey(method));
        add_type(method.owner);
        add_string(method.name);
        add_proto({method.return_type, method.parameter_types});
    };
    const auto add_method_handle = [&](const MethodHandleReference& handle) {
        std::string key = std::to_string(handle.handle_type) + ':';
        std::visit([&](const auto& member) {
            using Member = std::decay_t<decltype(member)>;
            if constexpr (std::is_same_v<Member, FieldReference>) {
                key += FieldKey(member);
                add_field(member);
            } else {
                key += MethodKey(member);
                add_method(member);
            }
        }, handle.member);
        result.method_handles.insert(std::move(key));
    };
    std::set<const EncodedArraySpec*> seen_arrays;
    std::set<const EncodedAnnotationSpec*> seen_annotations;
    std::function<void(const EncodedAnnotationSpec&)> add_annotation;
    std::function<void(const EncodedValueSpec&)> add_encoded;
    add_encoded = [&](const EncodedValueSpec& encoded) {
        std::visit([&](const auto& value) {
            using Value = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Value, ProtoReference>) {
                add_proto(value);
            } else if constexpr (std::is_same_v<Value, MethodHandleReference>) {
                add_method_handle(value);
            } else if constexpr (std::is_same_v<Value, StringReference>) {
                add_string(value.value);
            } else if constexpr (std::is_same_v<Value, TypeReference>) {
                add_type(value.descriptor);
            } else if constexpr (std::is_same_v<Value, FieldReference>) {
                add_field(value);
            } else if constexpr (std::is_same_v<Value, MethodReference>) {
                add_method(value);
            } else if constexpr (std::is_same_v<Value, EnumReference>) {
                add_field(value.field);
            } else if constexpr (std::is_same_v<
                                     Value, std::shared_ptr<EncodedArraySpec>>) {
                if (value && seen_arrays.insert(value.get()).second) {
                    for (const auto& item : value->values) add_encoded(item);
                }
            } else if constexpr (std::is_same_v<
                                     Value,
                                     std::shared_ptr<EncodedAnnotationSpec>>) {
                if (value && seen_annotations.insert(value.get()).second) {
                    add_annotation(*value);
                }
            }
        }, encoded.value);
    };
    add_annotation = [&](const EncodedAnnotationSpec& annotation) {
        add_type(annotation.type);
        for (const auto& element : annotation.elements) {
            add_string(element.name);
            add_encoded(element.value);
        }
    };
    const auto add_annotation_set = [&](const std::vector<AnnotationSpec>& annotations) {
        for (const auto& annotation : annotations) {
            add_annotation(annotation.annotation);
        }
    };

    add_type("Ljava/lang/Object;");
    add_type(klass.descriptor);
    if (klass.superclass.has_value()) add_type(*klass.superclass);
    for (const auto& interface_type : klass.interfaces) add_type(interface_type);
    if (klass.source_file.has_value()) add_string(*klass.source_file);
    add_annotation_set(klass.annotations);
    for (const auto* fields : {&klass.static_fields, &klass.instance_fields}) {
        for (const auto& field : *fields) {
            add_field({klass.descriptor, field.name, field.type});
            if (field.static_value.has_value()) add_encoded(*field.static_value);
            add_annotation_set(field.annotations);
        }
    }
    for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) {
            add_method({klass.descriptor, method.name, method.return_type,
                        method.parameter_types});
            for (const auto& patch : method.body.references) {
                std::visit([&](const auto& reference) {
                    using Reference = std::decay_t<decltype(reference)>;
                    if constexpr (std::is_same_v<Reference, std::string>) {
                        add_string(reference);
                    } else if constexpr (std::is_same_v<Reference, TypeReference>) {
                        add_type(reference.descriptor);
                    } else if constexpr (std::is_same_v<Reference, FieldReference>) {
                        add_field(reference);
                    } else if constexpr (std::is_same_v<Reference, MethodReference>) {
                        add_method(reference);
                    } else if constexpr (std::is_same_v<Reference, ProtoReference>) {
                        add_proto(reference);
                    } else if constexpr (std::is_same_v<Reference,
                                                        MethodHandleReference>) {
                        add_method_handle(reference);
                    } else {
                        if (!reference.values) {
                            throw std::invalid_argument(
                                "null call-site in class footprint");
                        }
                        result.call_sites.insert(std::to_string(
                            reinterpret_cast<std::uintptr_t>(reference.values.get())));
                        if (seen_arrays.insert(reference.values.get()).second) {
                            for (const auto& value : reference.values->values) {
                                add_encoded(value);
                            }
                        }
                    }
                }, patch.reference);
            }
            for (const auto& region : method.body.try_regions) {
                for (const auto& handler : region.handlers) {
                    if (handler.type.has_value()) add_type(*handler.type);
                }
            }
            if (method.body.debug_info.has_value()) {
                for (const auto& name : method.body.debug_info->parameter_names) {
                    if (name.has_value()) add_string(*name);
                }
                for (const auto& event : method.body.debug_info->events) {
                    if (event.name.has_value()) add_string(*event.name);
                    if (event.type.has_value()) add_type(*event.type);
                    if (event.signature.has_value()) add_string(*event.signature);
                    if (event.file.has_value()) add_string(*event.file);
                }
            }
            add_annotation_set(method.annotations);
            for (const auto& annotations : method.parameter_annotations) {
                add_annotation_set(annotations);
            }
        }
    }
    return result;
}

std::size_t FootprintWeight(const ClassFootprint& footprint) {
    return footprint.strings.size() + footprint.types.size() +
           footprint.protos.size() + footprint.fields.size() +
           footprint.methods.size() + footprint.call_sites.size() +
           footprint.method_handles.size();
}

} // namespace

class DexClassCloner::Impl final {
public:
    Impl(const DexFile& source, CloneOptions options)
        : source_(source), options_(options), reader_(source.bytes()) {}

    [[nodiscard]] ClassSpec Clone(std::size_t class_index) {
        if (class_index >= source_.classes().size()) {
            throw std::out_of_range("class clone index is out of range");
        }
        const auto& definition = source_.classes()[class_index];
        ClassSpec result;
        result.descriptor = source_.descriptor(definition.class_idx);
        result.superclass = definition.superclass_idx == kNoIndex ?
            std::nullopt :
            std::optional<std::string>(source_.descriptor(definition.superclass_idx));
        result.access_flags = definition.access_flags;
        for (const auto type : source_.type_list(definition.interfaces_off)) {
            result.interfaces.push_back(source_.descriptor(type));
        }
        if (definition.source_file_idx != kNoIndex) {
            result.source_file = source_.string(definition.source_file_idx);
        }

        const auto& data = source_.class_data(class_index);
        CloneFields(data.static_fields, result.static_fields);
        CloneFields(data.instance_fields, result.instance_fields);
        CloneMethods(data.direct_methods, result.direct_methods);
        CloneMethods(data.virtual_methods, result.virtual_methods);
        CloneStaticValues(definition, result);
        CloneAnnotations(definition, result);
        return result;
    }

private:
    [[nodiscard]] ProtoReference Proto(std::uint32_t index) const {
        if (index >= source_.protos().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, 0U,
                                "prototype index is invalid during cloning");
        }
        const auto& proto = source_.protos()[index];
        ProtoReference result;
        result.return_type = source_.descriptor(proto.return_type_idx);
        for (const auto type : source_.type_list(proto.parameters_off)) {
            result.parameter_types.push_back(source_.descriptor(type));
        }
        return result;
    }

    [[nodiscard]] FieldReference Field(std::uint32_t index) const {
        if (index >= source_.fields().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, 0U,
                                "field index is invalid during cloning");
        }
        const auto& field = source_.fields()[index];
        return {source_.descriptor(field.class_idx), source_.string(field.name_idx),
                source_.descriptor(field.type_idx)};
    }

    [[nodiscard]] MethodReference Method(std::uint32_t index) const {
        if (index >= source_.methods().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, 0U,
                                "method index is invalid during cloning");
        }
        const auto& method = source_.methods()[index];
        const auto proto = Proto(method.proto_idx);
        return {source_.descriptor(method.class_idx), source_.string(method.name_idx),
                proto.return_type, proto.parameter_types};
    }

    [[nodiscard]] MethodHandleReference MethodHandle(std::uint32_t index) const {
        if (index >= source_.method_handles().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, 0U,
                                "method-handle index is invalid during cloning");
        }
        const auto& handle = source_.method_handles()[index];
        if (handle.handle_type <= 3U) {
            return {handle.handle_type, Field(handle.member_idx)};
        }
        return {handle.handle_type, Method(handle.member_idx)};
    }

    [[nodiscard]] std::optional<std::string> OptionalString(
        std::uint32_t encoded_index, std::size_t offset) const {
        if (encoded_index == 0U) return std::nullopt;
        const auto index = encoded_index - 1U;
        if (index >= source_.strings().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, offset,
                                "debug string index is invalid");
        }
        return source_.string(index);
    }

    [[nodiscard]] std::optional<std::string> OptionalType(
        std::uint32_t encoded_index, std::size_t offset) const {
        if (encoded_index == 0U) return std::nullopt;
        const auto index = encoded_index - 1U;
        if (index >= source_.types().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, offset,
                                "debug type index is invalid");
        }
        return source_.descriptor(index);
    }

    [[nodiscard]] EncodedAnnotationSpec EncodedAnnotation(std::size_t& cursor) {
        const auto type_index = reader_.Uleb(cursor);
        if (type_index >= source_.types().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                "encoded annotation type index is invalid");
        }
        EncodedAnnotationSpec result;
        result.type = source_.descriptor(type_index);
        const auto size = reader_.Uleb(cursor);
        result.elements.reserve(size);
        std::optional<std::uint32_t> previous_name;
        for (std::uint32_t i = 0U; i < size; ++i) {
            const auto name_index = reader_.Uleb(cursor);
            if (name_index >= source_.strings().size() ||
                (previous_name.has_value() && name_index <= *previous_name)) {
                throw DexParseError(DexErrorCode::InvalidIndex, cursor,
                                    "encoded annotation element order is invalid");
            }
            previous_name = name_index;
            result.elements.push_back(
                {source_.string(name_index), EncodedValue(cursor)});
        }
        return result;
    }

    [[nodiscard]] EncodedValueSpec EncodedValue(std::size_t& cursor) {
        const auto header_offset = cursor;
        const auto header = reader_.U8(cursor++);
        const auto type = static_cast<std::uint8_t>(header & 0x1fU);
        const auto argument = static_cast<std::uint8_t>(header >> 5U);
        const auto width = static_cast<std::uint8_t>(argument + 1U);
        const auto unsigned_value = [&](std::uint8_t maximum_width) {
            if (width > maximum_width) {
                throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                    "encoded value width exceeds its value type");
            }
            return reader_.Unsigned(cursor, width);
        };
        const auto index_value = [&](std::size_t count, std::string_view label) {
            const auto value = unsigned_value(4U);
            if (value >= count) {
                throw DexParseError(DexErrorCode::InvalidIndex, header_offset,
                                    std::string(label) + " encoded index is invalid");
            }
            return static_cast<std::uint32_t>(value);
        };
        switch (type) {
            case 0x00U:
                if (argument != 0U) {
                    throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                        "encoded byte has an invalid value_arg");
                }
                return {static_cast<std::int8_t>(unsigned_value(1U))};
            case 0x02U:
                return {static_cast<std::int16_t>(
                    SignExtend(unsigned_value(2U), width))};
            case 0x03U:
                return {static_cast<char16_t>(unsigned_value(2U))};
            case 0x04U:
                return {static_cast<std::int32_t>(
                    SignExtend(unsigned_value(4U), width))};
            case 0x06U:
                return {SignExtend(unsigned_value(8U), width)};
            case 0x10U: {
                const auto bits = static_cast<std::uint32_t>(unsigned_value(4U)) <<
                                  ((4U - width) * 8U);
                return {std::bit_cast<float>(bits)};
            }
            case 0x11U: {
                const auto bits = unsigned_value(8U) << ((8U - width) * 8U);
                return {std::bit_cast<double>(bits)};
            }
            case 0x15U: return {Proto(index_value(source_.protos().size(), "proto"))};
            case 0x16U:
                return {MethodHandle(index_value(source_.method_handles().size(),
                                                 "method-handle"))};
            case 0x17U:
                return {StringReference{
                    source_.string(index_value(source_.strings().size(), "string"))}};
            case 0x18U:
                return {TypeReference{
                    source_.descriptor(index_value(source_.types().size(), "type"))}};
            case 0x19U:
                return {Field(index_value(source_.fields().size(), "field"))};
            case 0x1aU:
                return {Method(index_value(source_.methods().size(), "method"))};
            case 0x1bU:
                return {EnumReference{
                    Field(index_value(source_.fields().size(), "enum"))}};
            case 0x1cU: {
                if (argument != 0U) {
                    throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                        "encoded array has an invalid value_arg");
                }
                auto array = std::make_shared<EncodedArraySpec>();
                const auto size = reader_.Uleb(cursor);
                array->values.reserve(size);
                for (std::uint32_t i = 0U; i < size; ++i) {
                    array->values.push_back(EncodedValue(cursor));
                }
                return {std::move(array)};
            }
            case 0x1dU: {
                if (argument != 0U) {
                    throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                        "encoded annotation has an invalid value_arg");
                }
                return {std::make_shared<EncodedAnnotationSpec>(
                    EncodedAnnotation(cursor))};
            }
            case 0x1eU:
                if (argument != 0U) {
                    throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                        "encoded null has an invalid value_arg");
                }
                return {NullEncodedValue{}};
            case 0x1fU:
                if (argument > 1U) {
                    throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                        "encoded boolean has an invalid value_arg");
                }
                return {argument != 0U};
            default:
                throw DexParseError(DexErrorCode::InvalidClassData, header_offset,
                                    "unknown encoded value type");
        }
    }

    [[nodiscard]] std::shared_ptr<EncodedArraySpec> CallSite(std::uint32_t index) {
        if (index >= source_.call_sites().size()) {
            throw DexParseError(DexErrorCode::InvalidIndex, 0U,
                                "call-site index is invalid during cloning");
        }
        const auto found = call_sites_.find(index);
        if (found != call_sites_.end()) return found->second;
        std::size_t cursor = source_.call_sites()[index].encoded_array_off;
        auto result = std::make_shared<EncodedArraySpec>();
        const auto size = reader_.Uleb(cursor);
        result->values.reserve(size);
        for (std::uint32_t i = 0U; i < size; ++i) {
            result->values.push_back(EncodedValue(cursor));
        }
        call_sites_.emplace(index, result);
        return result;
    }

    [[nodiscard]] AnnotationSpec Annotation(std::uint32_t offset) {
        std::size_t cursor = offset;
        const auto visibility = reader_.U8(cursor++);
        if (visibility > 2U) {
            throw DexParseError(DexErrorCode::InvalidClassData, offset,
                                "annotation visibility is invalid");
        }
        return {visibility, EncodedAnnotation(cursor)};
    }

    [[nodiscard]] std::vector<AnnotationSpec> AnnotationSet(
        std::uint32_t offset) {
        if (offset == 0U) return {};
        const auto size = reader_.U32(offset);
        std::vector<AnnotationSpec> result;
        result.reserve(size);
        for (std::uint32_t i = 0U; i < size; ++i) {
            result.push_back(Annotation(reader_.U32(
                static_cast<std::size_t>(offset) + 4U +
                static_cast<std::size_t>(i) * 4U)));
        }
        return result;
    }

    [[nodiscard]] std::vector<std::vector<AnnotationSpec>> ParameterAnnotations(
        std::uint32_t offset) {
        if (offset == 0U) return {};
        const auto size = reader_.U32(offset);
        std::vector<std::vector<AnnotationSpec>> result;
        result.reserve(size);
        for (std::uint32_t i = 0U; i < size; ++i) {
            result.push_back(AnnotationSet(reader_.U32(
                static_cast<std::size_t>(offset) + 4U +
                static_cast<std::size_t>(i) * 4U)));
        }
        return result;
    }

    [[nodiscard]] DebugInfoSpec DebugInfo(std::uint32_t offset) const {
        std::size_t cursor = offset;
        DebugInfoSpec result;
        result.line_start = reader_.Uleb(cursor);
        const auto parameters = reader_.Uleb(cursor);
        result.parameter_names.reserve(parameters);
        for (std::uint32_t i = 0U; i < parameters; ++i) {
            const auto at = cursor;
            result.parameter_names.push_back(OptionalString(reader_.Uleb(cursor), at));
        }
        for (;;) {
            const auto opcode_offset = cursor;
            const auto opcode = reader_.U8(cursor++);
            if (opcode == 0x00U) break;
            DebugEventSpec event;
            if (opcode == 0x01U) {
                event.kind = DebugEventKind::AdvancePc;
                event.address_difference = reader_.Uleb(cursor);
            } else if (opcode == 0x02U) {
                event.kind = DebugEventKind::AdvanceLine;
                event.line_difference = reader_.Sleb(cursor);
            } else if (opcode == 0x03U || opcode == 0x04U) {
                event.kind = opcode == 0x03U ? DebugEventKind::StartLocal :
                                               DebugEventKind::StartLocalExtended;
                event.register_index = reader_.Uleb(cursor);
                auto at = cursor;
                event.name = OptionalString(reader_.Uleb(cursor), at);
                at = cursor;
                event.type = OptionalType(reader_.Uleb(cursor), at);
                if (opcode == 0x04U) {
                    at = cursor;
                    event.signature = OptionalString(reader_.Uleb(cursor), at);
                }
            } else if (opcode == 0x05U || opcode == 0x06U) {
                event.kind = opcode == 0x05U ? DebugEventKind::EndLocal :
                                               DebugEventKind::RestartLocal;
                event.register_index = reader_.Uleb(cursor);
            } else if (opcode == 0x07U) {
                event.kind = DebugEventKind::SetPrologueEnd;
            } else if (opcode == 0x08U) {
                event.kind = DebugEventKind::SetEpilogueBegin;
            } else if (opcode == 0x09U) {
                event.kind = DebugEventKind::SetFile;
                const auto at = cursor;
                event.file = OptionalString(reader_.Uleb(cursor), at);
            } else if (opcode >= 0x0aU) {
                event.kind = DebugEventKind::Special;
                event.special_opcode = opcode;
            } else {
                throw DexParseError(DexErrorCode::InvalidClassData, opcode_offset,
                                    "unknown debug opcode");
            }
            result.events.push_back(std::move(event));
        }
        return result;
    }

    void AddCodeReferences(const CodeItem& code, MethodBodySpec& body) {
        const auto add = [&](MethodBodySpec::SymbolicReference reference,
                             const DecodedInstruction& instruction,
                             std::size_t word, bool wide = false) {
            body.references.push_back(
                {std::move(reference), instruction.offset +
                                      static_cast<std::uint32_t>(word), wide});
        };
        for (const auto& instruction : code.instructions) {
            const auto opcode = instruction.opcode;
            if (opcode == 0x1aU) {
                add(source_.string(InstructionReference(instruction, 1U)),
                    instruction, 1U);
            } else if (opcode == 0x1bU) {
                add(source_.string(InstructionReference(instruction, 1U, true)),
                    instruction, 1U, true);
            } else if (opcode == 0x1cU || opcode == 0x1fU || opcode == 0x20U ||
                       opcode == 0x22U || opcode == 0x23U || opcode == 0x24U ||
                       opcode == 0x25U) {
                add(TypeReference{source_.descriptor(
                        InstructionReference(instruction, 1U))},
                    instruction, 1U);
            } else if (opcode >= 0x52U && opcode <= 0x6dU) {
                add(Field(InstructionReference(instruction, 1U)), instruction, 1U);
            } else if ((opcode >= 0x6eU && opcode <= 0x72U) ||
                       (opcode >= 0x74U && opcode <= 0x78U)) {
                add(Method(InstructionReference(instruction, 1U)), instruction, 1U);
            } else if (opcode == 0xfaU || opcode == 0xfbU) {
                add(Method(InstructionReference(instruction, 1U)), instruction, 1U);
                add(Proto(InstructionReference(instruction, 3U)), instruction, 3U);
            } else if (opcode == 0xfcU || opcode == 0xfdU) {
                add(CallSiteReference{
                        CallSite(InstructionReference(instruction, 1U))},
                    instruction, 1U);
            } else if (opcode == 0xfeU) {
                add(MethodHandle(InstructionReference(instruction, 1U)),
                    instruction, 1U);
            } else if (opcode == 0xffU) {
                add(Proto(InstructionReference(instruction, 1U)), instruction, 1U);
            }
        }
    }

    [[nodiscard]] MethodSpec CloneMethod(const DexEncodedMethod& encoded) {
        const auto reference = Method(encoded.method_idx);
        MethodSpec result;
        result.name = reference.name;
        result.return_type = reference.return_type;
        result.parameter_types = reference.parameter_types;
        result.access_flags = encoded.access_flags;
        if (encoded.code_off == 0U) return result;
        const auto code = DecodeCodeItem(source_, encoded.code_off);
        result.body.registers_size = code.registers_size;
        result.body.ins_size = code.ins_size;
        result.body.outs_size = code.outs_size;
        result.body.code_units = code.insns;
        AddCodeReferences(code, result.body);
        for (const auto& region : code.tries) {
            MethodBodySpec::TryRegionSpec cloned_region;
            cloned_region.start_address = region.start_address;
            cloned_region.instruction_count = region.instruction_count;
            for (const auto& handler : region.handlers) {
                cloned_region.handlers.push_back({
                    handler.type_idx.has_value() ?
                        std::optional<std::string>(
                            source_.descriptor(*handler.type_idx)) : std::nullopt,
                    handler.address});
            }
            result.body.try_regions.push_back(std::move(cloned_region));
        }
        if (options_.preserve_debug_info && code.debug_info_off != 0U) {
            result.body.debug_info = DebugInfo(code.debug_info_off);
            if (result.body.debug_info->parameter_names.size() !=
                result.parameter_types.size()) {
                throw DexParseError(DexErrorCode::InvalidClassData,
                                    code.debug_info_off,
                                    "debug parameter count does not match prototype");
            }
        }
        return result;
    }

    void CloneFields(const std::vector<DexEncodedField>& source_fields,
                     std::vector<FieldSpec>& destination) const {
        destination.reserve(source_fields.size());
        for (const auto& encoded : source_fields) {
            const auto reference = Field(encoded.field_idx);
            FieldSpec field;
            field.name = reference.name;
            field.type = reference.type;
            field.access_flags = encoded.access_flags;
            destination.push_back(std::move(field));
        }
    }

    void CloneMethods(const std::vector<DexEncodedMethod>& source_methods,
                      std::vector<MethodSpec>& destination) {
        destination.reserve(source_methods.size());
        for (const auto& encoded : source_methods) {
            destination.push_back(CloneMethod(encoded));
        }
    }

    void CloneStaticValues(const DexClassDef& definition, ClassSpec& result) {
        if (definition.static_values_off == 0U) return;
        std::size_t cursor = definition.static_values_off;
        const auto count = reader_.Uleb(cursor);
        if (count > result.static_fields.size()) {
            throw DexParseError(DexErrorCode::InvalidClassData,
                                definition.static_values_off,
                                "static value count exceeds static fields");
        }
        for (std::uint32_t i = 0U; i < count; ++i) {
            result.static_fields[i].static_value = EncodedValue(cursor);
        }
    }

    void CloneAnnotations(const DexClassDef& definition, ClassSpec& result) {
        if (definition.annotations_off == 0U) return;
        auto cursor = static_cast<std::size_t>(definition.annotations_off);
        const auto class_annotations = reader_.U32(cursor); cursor += 4U;
        const auto fields_size = reader_.U32(cursor); cursor += 4U;
        const auto methods_size = reader_.U32(cursor); cursor += 4U;
        const auto parameters_size = reader_.U32(cursor); cursor += 4U;
        result.annotations = AnnotationSet(class_annotations);

        const auto& data = source_.class_data(
            static_cast<std::size_t>(&definition - source_.classes().data()));
        std::map<std::uint32_t, FieldSpec*> fields;
        for (std::size_t i = 0U; i < data.static_fields.size(); ++i) {
            fields.emplace(data.static_fields[i].field_idx, &result.static_fields[i]);
        }
        for (std::size_t i = 0U; i < data.instance_fields.size(); ++i) {
            fields.emplace(data.instance_fields[i].field_idx, &result.instance_fields[i]);
        }
        std::map<std::uint32_t, MethodSpec*> methods;
        for (std::size_t i = 0U; i < data.direct_methods.size(); ++i) {
            methods.emplace(data.direct_methods[i].method_idx, &result.direct_methods[i]);
        }
        for (std::size_t i = 0U; i < data.virtual_methods.size(); ++i) {
            methods.emplace(data.virtual_methods[i].method_idx, &result.virtual_methods[i]);
        }
        for (std::uint32_t i = 0U; i < fields_size; ++i) {
            const auto index = reader_.U32(cursor);
            const auto offset = reader_.U32(cursor + 4U);
            cursor += 8U;
            const auto found = fields.find(index);
            if (found == fields.end()) {
                throw DexParseError(DexErrorCode::InvalidIndex, cursor - 8U,
                                    "annotation directory field is not in class");
            }
            found->second->annotations = AnnotationSet(offset);
        }
        for (std::uint32_t i = 0U; i < methods_size; ++i) {
            const auto index = reader_.U32(cursor);
            const auto offset = reader_.U32(cursor + 4U);
            cursor += 8U;
            const auto found = methods.find(index);
            if (found == methods.end()) {
                throw DexParseError(DexErrorCode::InvalidIndex, cursor - 8U,
                                    "annotation directory method is not in class");
            }
            found->second->annotations = AnnotationSet(offset);
        }
        for (std::uint32_t i = 0U; i < parameters_size; ++i) {
            const auto index = reader_.U32(cursor);
            const auto offset = reader_.U32(cursor + 4U);
            cursor += 8U;
            const auto found = methods.find(index);
            if (found == methods.end()) {
                throw DexParseError(DexErrorCode::InvalidIndex, cursor - 8U,
                                    "annotation directory parameter method is not in class");
            }
            found->second->parameter_annotations = ParameterAnnotations(offset);
            if (found->second->parameter_annotations.size() !=
                found->second->parameter_types.size()) {
                throw DexParseError(DexErrorCode::InvalidClassData, offset,
                                    "parameter annotation count does not match prototype");
            }
        }
    }

    const DexFile& source_;
    CloneOptions options_;
    Reader reader_;
    std::map<std::uint32_t, std::shared_ptr<EncodedArraySpec>> call_sites_;
};

DexClassCloner::DexClassCloner(const DexFile& source, CloneOptions options)
    : impl_(std::make_unique<Impl>(source, options)) {}

DexClassCloner::~DexClassCloner() = default;
DexClassCloner::DexClassCloner(DexClassCloner&&) noexcept = default;
DexClassCloner& DexClassCloner::operator=(DexClassCloner&&) noexcept = default;

ClassSpec DexClassCloner::Clone(std::size_t class_index) {
    return impl_->Clone(class_index);
}

RepartitionedDex BuildDexPartition(const DexProgram& program,
                                   std::span<const ClassHandle> classes,
                                   const CloneOptions& options,
                                   std::optional<std::uint32_t> output_version) {
    if (classes.empty()) {
        throw std::invalid_argument("cannot build an empty DEX partition");
    }
    std::uint32_t version = output_version.value_or(35U);
    if (!output_version.has_value()) {
        for (const auto handle : classes) {
            version = std::max<std::uint32_t>(version,
                program.dex(handle.dex_index).version());
        }
    }
    DexBuilder builder(version);
    std::vector<std::unique_ptr<DexClassCloner>> cloners(program.dex_count());
    for (const auto handle : classes) {
        if (handle.dex_index >= program.dex_count()) {
            throw std::out_of_range("partition class DEX index is invalid");
        }
        if (!cloners[handle.dex_index]) {
            cloners[handle.dex_index] = std::make_unique<DexClassCloner>(
                program.dex(handle.dex_index), options);
        }
        builder.AddClass(cloners[handle.dex_index]->Clone(handle.class_index));
    }
    auto bytes = builder.Build();
    const auto dex = DexFile::Parse(bytes);
    VerifyDexOrThrow(dex, VerificationLevel::Full);
    return {std::move(bytes), std::vector<ClassHandle>(classes.begin(), classes.end()),
            version};
}

std::vector<RepartitionedDex> RepartitionProgram(
    const DexProgram& program, const RepartitionOptions& options) {
    options.partition.limits.Validate();
    struct Candidate {
        ClassHandle handle;
        std::string descriptor;
        ClassFootprint footprint;
        bool primary{};
    };
    std::vector<std::unique_ptr<DexClassCloner>> cloners(program.dex_count());
    std::map<ClassHandle, ClassSpec> specs;
    std::vector<Candidate> candidates;
    const auto class_handles = program.classes();
    for (std::size_t class_ordinal = 0U;
         class_ordinal < class_handles.size(); ++class_ordinal) {
        const auto handle = class_handles[class_ordinal];
        if (!cloners[handle.dex_index]) {
            cloners[handle.dex_index] = std::make_unique<DexClassCloner>(
                program.dex(handle.dex_index), options.clone);
        }
        auto spec = cloners[handle.dex_index]->Clone(handle.class_index);
        auto footprint = CollectSpecFootprint(spec);
        const auto descriptor = spec.descriptor;
        const auto primary =
            options.partition.primary_dex_classes.contains(descriptor);
        specs.emplace(handle, std::move(spec));
        candidates.push_back(
            {handle, descriptor, std::move(footprint), primary});
        if (options.progress &&
            ((class_ordinal + 1U) % 256U == 0U ||
             class_ordinal + 1U == class_handles.size())) {
            options.progress(class_ordinal + 1U, class_handles.size(),
                             "clone-and-measure");
        }
    }
    if (candidates.empty()) return {};
    if (!options.partition.preserve_input_order) {
        std::stable_sort(candidates.begin(), candidates.end(),
            [](const auto& left, const auto& right) {
                if (left.primary != right.primary) return left.primary > right.primary;
                return FootprintWeight(left.footprint) >
                       FootprintWeight(right.footprint);
            });
    }
    std::vector<DexPartition> partitions(1U);
    const auto add = [&](DexPartition& partition, const Candidate& candidate) {
        if (!ClassFootprintFits(partition.footprint, candidate.footprint,
                                options.partition.limits)) {
            return false;
        }
        partition.classes.push_back(candidate.handle);
        MergeClassFootprint(partition.footprint, candidate.footprint);
        return true;
    };
    for (const auto& candidate : candidates) {
        if (!candidate.primary) continue;
        if (!add(partitions.front(), candidate)) {
            throw std::runtime_error(
                "primary DEX classes exceed configured ID limits at " +
                candidate.descriptor);
        }
    }
    for (const auto& candidate : candidates) {
        if (candidate.primary) continue;
        if (!ClassFootprintFits({}, candidate.footprint,
                                options.partition.limits)) {
            throw std::runtime_error(
                "class footprint exceeds configured DEX ID limits: " +
                candidate.descriptor);
        }
        bool placed = false;
        if (options.partition.preserve_input_order) {
            placed = add(partitions.back(), candidate);
        } else {
            for (auto& partition : partitions) {
                if (add(partition, candidate)) {
                    placed = true;
                    break;
                }
            }
        }
        if (!placed) {
            partitions.emplace_back();
            if (!add(partitions.back(), candidate)) {
                throw std::logic_error(
                    "failed to add class to an empty exact DEX partition");
            }
        }
    }

    std::vector<RepartitionedDex> result;
    result.reserve(partitions.size());
    for (std::size_t partition_index = 0U;
         partition_index < partitions.size(); ++partition_index) {
        const auto& partition = partitions[partition_index];
        auto version = options.output_version.value_or(35U);
        if (!options.output_version.has_value()) {
            for (const auto handle : partition.classes) {
                version = std::max<std::uint32_t>(
                    version, program.dex(handle.dex_index).version());
            }
        }
        DexBuilder builder(version);
        for (const auto handle : partition.classes) {
            auto found = specs.find(handle);
            if (found == specs.end()) {
                throw std::logic_error("cloned class disappeared during repartition");
            }
            builder.AddClass(std::move(found->second));
        }
        auto bytes = builder.Build();
        VerifyDexOrThrow(DexFile::Parse(bytes), VerificationLevel::Full);
        result.push_back({std::move(bytes), partition.classes, version});
        if (options.progress) {
            options.progress(partition_index + 1U, partitions.size(), "write");
        }
    }
    return result;
}

} // namespace birch::dex
