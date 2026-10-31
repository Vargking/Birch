#include "birch/dex/builder.h"

#include "birch/dex/checksum.h"
#include "birch/dex/remap.h"

#include <algorithm>
#include <array>
#include <bit>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <type_traits>

namespace birch::dex {
namespace {

constexpr std::uint32_t kNoIndex = 0xffffffffU;

void WriteU16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void WriteU32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8U));
    out.push_back(static_cast<std::uint8_t>(value >> 16U));
    out.push_back(static_cast<std::uint8_t>(value >> 24U));
}

void PatchU32(std::vector<std::uint8_t>& out, std::size_t offset, std::uint32_t value) {
    if (offset > out.size() || out.size() - offset < 4U) throw std::logic_error("DEX patch exceeds output");
    for (unsigned shift = 0; shift < 32U; shift += 8U) out[offset + shift / 8U] = static_cast<std::uint8_t>(value >> shift);
}

void WriteUleb(std::vector<std::uint8_t>& out, std::uint32_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) byte = static_cast<std::uint8_t>(byte | 0x80U);
        out.push_back(byte);
    } while (value != 0U);
}

void WriteSleb(std::vector<std::uint8_t>& out, std::int32_t value) {
    bool more = true;
    while (more) {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        const auto sign = (byte & 0x40U) != 0U;
        value >>= 7;
        more = !((value == 0 && !sign) || (value == -1 && sign));
        if (more) byte = static_cast<std::uint8_t>(byte | 0x80U);
        out.push_back(byte);
    }
}

void Align(std::vector<std::uint8_t>& out, std::size_t alignment) {
    while ((out.size() % alignment) != 0U) out.push_back(0U);
}

std::vector<std::uint32_t> DecodeUtf8(std::string_view text) {
    std::vector<std::uint32_t> result;
    for (std::size_t cursor = 0; cursor < text.size();) {
        const auto first = static_cast<std::uint8_t>(text[cursor]);
        std::uint32_t value = 0U;
        std::size_t width = 0U;
        std::uint32_t minimum = 0U;
        if (first <= 0x7fU) { value = first; width = 1U; }
        else if (first == 0xc0U && cursor + 1U < text.size() &&
                 static_cast<std::uint8_t>(text[cursor + 1U]) == 0x80U) {
            // DEX stores U+0000 as the two-byte MUTF-8 sequence C0 80.
            value = 0U; width = 2U;
        }
        else if (first >= 0xc2U && first <= 0xdfU) { value = first & 0x1fU; width = 2U; minimum = 0x80U; }
        else if (first >= 0xe0U && first <= 0xefU) { value = first & 0x0fU; width = 3U; minimum = 0x800U; }
        else if (first >= 0xf0U && first <= 0xf4U) { value = first & 0x07U; width = 4U; minimum = 0x10000U; }
        else throw std::invalid_argument("invalid UTF-8 in DEX string");
        if (text.size() - cursor < width) throw std::invalid_argument("truncated UTF-8 in DEX string");
        for (std::size_t i = 1; i < width; ++i) {
            const auto next = static_cast<std::uint8_t>(text[cursor + i]);
            if ((next & 0xc0U) != 0x80U) throw std::invalid_argument("invalid UTF-8 continuation");
            value = (value << 6U) | (next & 0x3fU);
        }
        if (value < minimum || value > 0x10ffffU) {
            throw std::invalid_argument("invalid UTF-8 scalar value");
        }
        result.push_back(value);
        cursor += width;
    }
    return result;
}

std::vector<std::uint16_t> Utf16(std::string_view text) {
    std::vector<std::uint16_t> result;
    for (const auto value : DecodeUtf8(text)) {
        if (value <= 0xffffU) result.push_back(static_cast<std::uint16_t>(value));
        else {
            const auto adjusted = value - 0x10000U;
            result.push_back(static_cast<std::uint16_t>(0xd800U + (adjusted >> 10U)));
            result.push_back(static_cast<std::uint16_t>(0xdc00U + (adjusted & 0x3ffU)));
        }
    }
    return result;
}

std::vector<std::uint8_t> Mutf8(std::string_view text) {
    std::vector<std::uint8_t> result;
    for (const auto unit : Utf16(text)) {
        if (unit != 0U && unit <= 0x7fU) result.push_back(static_cast<std::uint8_t>(unit));
        else if (unit <= 0x7ffU) {
            result.push_back(static_cast<std::uint8_t>(0xc0U | (unit >> 6U)));
            result.push_back(static_cast<std::uint8_t>(0x80U | (unit & 0x3fU)));
        } else {
            result.push_back(static_cast<std::uint8_t>(0xe0U | (unit >> 12U)));
            result.push_back(static_cast<std::uint8_t>(0x80U | ((unit >> 6U) & 0x3fU)));
            result.push_back(static_cast<std::uint8_t>(0x80U | (unit & 0x3fU)));
        }
    }
    return result;
}

std::string Shorty(const MethodSpec& method) {
    auto short_type = [](std::string_view type) { return type.starts_with('L') || type.starts_with('[') ? 'L' : type.front(); };
    std::string result(1U, short_type(method.return_type));
    for (const auto& type : method.parameter_types) result.push_back(short_type(type));
    return result;
}

struct ProtoKey {
    std::string return_type;
    std::vector<std::string> parameters;
    auto operator<=>(const ProtoKey&) const = default;
};

struct MethodKey {
    std::string owner;
    std::string name;
    ProtoKey proto;
    auto operator<=>(const MethodKey&) const = default;
};

struct FieldKey {
    std::string owner;
    std::string name;
    std::string type;
    auto operator<=>(const FieldKey&) const = default;
};

struct MethodHandleKey {
    std::uint16_t handle_type{};
    std::variant<FieldKey, MethodKey> member;
    auto operator<=>(const MethodHandleKey&) const = default;
};

struct MapEntry { std::uint16_t type; std::uint32_t count; std::uint32_t offset; };

MethodKey ToMethodKey(const MethodReference& reference) {
    return {reference.owner, reference.name,
            {reference.return_type, reference.parameter_types}};
}

FieldKey ToFieldKey(const FieldReference& reference) {
    return {reference.owner, reference.name, reference.type};
}

MethodHandleKey ToMethodHandleKey(const MethodHandleReference& reference) {
    if (reference.handle_type > 8U) {
        throw std::invalid_argument("DEX method handle type is invalid");
    }
    if (reference.handle_type <= 3U) {
        const auto* field = std::get_if<FieldReference>(&reference.member);
        if (field == nullptr) {
            throw std::invalid_argument("field method handle requires a field reference");
        }
        return {reference.handle_type, ToFieldKey(*field)};
    }
    const auto* method = std::get_if<MethodReference>(&reference.member);
    if (method == nullptr) {
        throw std::invalid_argument("invoke method handle requires a method reference");
    }
    return {reference.handle_type, ToMethodKey(*method)};
}

void WriteUlebp1(std::vector<std::uint8_t>& out,
                 const std::optional<std::uint32_t>& value) {
    WriteUleb(out, value.has_value() ? *value + 1U : 0U);
}

template <typename Unsigned>
std::uint8_t MinimalUnsignedBytes(Unsigned value) {
    static_assert(std::is_unsigned_v<Unsigned>);
    std::uint8_t size = 1U;
    while (size < sizeof(Unsigned) && (value >> (size * 8U)) != 0U) ++size;
    return size;
}

template <typename Signed>
std::uint8_t MinimalSignedBytes(Signed value) {
    static_assert(std::is_signed_v<Signed>);
    auto size = static_cast<std::uint8_t>(sizeof(Signed));
    while (size > 1U) {
        const auto shift = static_cast<unsigned>((size - 1U) * 8U);
        const auto top = static_cast<std::uint8_t>(
            static_cast<std::make_unsigned_t<Signed>>(value) >> shift);
        const auto next = static_cast<std::uint8_t>(
            static_cast<std::make_unsigned_t<Signed>>(value) >> (shift - 8U));
        if ((top == 0U && (next & 0x80U) == 0U) ||
            (top == 0xffU && (next & 0x80U) != 0U)) {
            --size;
        } else {
            break;
        }
    }
    return size;
}

template <typename Unsigned>
void WriteEncodedScalar(std::vector<std::uint8_t>& out, std::uint8_t value_type,
                        Unsigned value, std::uint8_t width) {
    out.push_back(static_cast<std::uint8_t>(value_type | ((width - 1U) << 5U)));
    for (std::uint8_t i = 0U; i < width; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8U)));
    }
}

} // namespace

DexBuilder::DexBuilder(std::uint32_t version) : version_(version) {
    if (version != 35U && version != 37U && version != 38U && version != 39U && version != 40U && version != 41U) {
        throw std::invalid_argument("unsupported DEX builder version");
    }
}

void DexBuilder::AddClass(ClassSpec spec) {
    if (spec.descriptor.size() < 3U || spec.descriptor.front() != 'L' || spec.descriptor.back() != ';') {
        throw std::invalid_argument("class descriptor must have L...; form");
    }
    if (!class_descriptors_.insert(spec.descriptor).second) {
        throw std::invalid_argument("duplicate class in DEX builder");
    }
    classes_.push_back(std::move(spec));
}

void DexBuilder::AddString(std::string value) {
    extra_strings_.push_back(std::move(value));
}

std::vector<std::uint8_t> DexBuilder::Build(CodeAddressMaps* addresses) const {
    if (classes_.empty()) throw std::invalid_argument("DEX builder has no classes");
    std::set<std::string> string_set;
    string_set.insert(extra_strings_.begin(), extra_strings_.end());
    std::set<std::string> type_set{"Ljava/lang/Object;"};
    std::set<ProtoKey> proto_set;
    std::vector<MethodKey> method_keys;
    std::vector<FieldKey> field_keys;
    std::set<MethodHandleKey> method_handle_set;
    std::vector<std::shared_ptr<EncodedArraySpec>> call_sites;
    std::map<const EncodedArraySpec*, std::uint32_t> call_site_ordinals;
    const auto references = [](const MethodBodySpec& body) {
        std::vector<MethodBodySpec::ReferencePatch> result = body.references;
        for (const auto& patch : body.invoke_references) {
            result.push_back({patch.reference, patch.code_unit, false});
        }
        if (body.invoke_reference.has_value()) {
            result.push_back({*body.invoke_reference, body.invoke_reference_unit, false});
        }
        for (const auto& patch : body.string_references) {
            result.push_back({patch.value, patch.code_unit, false});
        }
        std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
            return left.code_unit < right.code_unit;
        });
        for (std::size_t i = 1U; i < result.size(); ++i) {
            const auto previous_end = result[i - 1U].code_unit +
                                      (result[i - 1U].wide ? 2U : 1U);
            if (previous_end > result[i].code_unit) {
                throw std::invalid_argument("overlapping symbolic reference patches");
            }
        }
        return result;
    };
    const auto add_proto_reference = [&](const ProtoReference& reference) {
        type_set.insert(reference.return_type);
        for (const auto& parameter : reference.parameter_types) {
            type_set.insert(parameter);
        }
        proto_set.insert({reference.return_type, reference.parameter_types});
        MethodSpec temporary;
        temporary.return_type = reference.return_type;
        temporary.parameter_types = reference.parameter_types;
        string_set.insert(Shorty(temporary));
    };
    const auto add_field_reference = [&](const FieldReference& reference) {
        type_set.insert(reference.owner);
        type_set.insert(reference.type);
        string_set.insert(reference.name);
        field_keys.push_back(ToFieldKey(reference));
    };
    const auto add_method_reference = [&](const MethodReference& reference) {
        type_set.insert(reference.owner);
        string_set.insert(reference.name);
        add_proto_reference({reference.return_type, reference.parameter_types});
        method_keys.push_back(ToMethodKey(reference));
    };
    const auto add_method_handle = [&](const MethodHandleReference& reference) {
        const auto key = ToMethodHandleKey(reference);
        if (const auto* field = std::get_if<FieldKey>(&key.member)) {
            add_field_reference({field->owner, field->name, field->type});
        } else {
            const auto& method = std::get<MethodKey>(key.member);
            add_method_reference({method.owner, method.name, method.proto.return_type,
                                  method.proto.parameters});
        }
        method_handle_set.insert(key);
    };
    std::function<void(const EncodedAnnotationSpec&)> collect_annotation;
    std::function<void(const EncodedValueSpec&)> collect_encoded_value;
    collect_encoded_value = [&](const EncodedValueSpec& encoded) {
        std::visit([&](const auto& value) {
            using Value = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Value, ProtoReference>) {
                add_proto_reference(value);
            } else if constexpr (std::is_same_v<Value, MethodHandleReference>) {
                add_method_handle(value);
            } else if constexpr (std::is_same_v<Value, StringReference>) {
                string_set.insert(value.value);
            } else if constexpr (std::is_same_v<Value, TypeReference>) {
                type_set.insert(value.descriptor);
            } else if constexpr (std::is_same_v<Value, FieldReference>) {
                add_field_reference(value);
            } else if constexpr (std::is_same_v<Value, MethodReference>) {
                add_method_reference(value);
            } else if constexpr (std::is_same_v<Value, EnumReference>) {
                add_field_reference(value.field);
            } else if constexpr (std::is_same_v<Value,
                                                std::shared_ptr<EncodedArraySpec>>) {
                if (!value) throw std::invalid_argument("null encoded array value");
                for (const auto& item : value->values) collect_encoded_value(item);
            } else if constexpr (std::is_same_v<
                                     Value,
                                     std::shared_ptr<EncodedAnnotationSpec>>) {
                if (!value) throw std::invalid_argument("null encoded annotation value");
                collect_annotation(*value);
            }
        }, encoded.value);
    };
    collect_annotation = [&](const EncodedAnnotationSpec& annotation) {
        type_set.insert(annotation.type);
        std::set<std::string> names;
        for (const auto& element : annotation.elements) {
            if (element.name.empty() || !names.insert(element.name).second) {
                throw std::invalid_argument("invalid or duplicate annotation element name");
            }
            string_set.insert(element.name);
            collect_encoded_value(element.value);
        }
    };
    const auto collect_annotation_set = [&](const std::vector<AnnotationSpec>& set) {
        std::set<std::string> types;
        for (const auto& item : set) {
            if (item.visibility > 2U) {
                throw std::invalid_argument("invalid annotation visibility");
            }
            if (!types.insert(item.annotation.type).second) {
                throw std::invalid_argument("duplicate annotation type in set");
            }
            collect_annotation(item.annotation);
        }
    };
    const auto add_call_site = [&](const CallSiteReference& reference) {
        if (!reference.values) throw std::invalid_argument("null call-site value array");
        if (!call_site_ordinals.contains(reference.values.get())) {
            const auto ordinal = static_cast<std::uint32_t>(call_sites.size());
            call_site_ordinals.emplace(reference.values.get(), ordinal);
            call_sites.push_back(reference.values);
            for (const auto& item : reference.values->values) {
                collect_encoded_value(item);
            }
        }
    };
    for (const auto& klass : classes_) {
        type_set.insert(klass.descriptor);
        if (klass.superclass.has_value()) type_set.insert(*klass.superclass);
        std::set<std::pair<std::string, std::string>> declared_fields;
        for (const auto* fields : {&klass.static_fields, &klass.instance_fields}) {
            for (const auto& field : *fields) {
                if (!declared_fields.emplace(field.name, field.type).second) {
                    throw std::invalid_argument("duplicate field definition in class");
                }
            }
        }
        for (const auto& field : klass.instance_fields) {
            if (field.static_value.has_value()) {
                throw std::invalid_argument(
                    "instance field cannot have a static encoded value");
            }
        }
        std::set<std::tuple<std::string, std::string,
                            std::vector<std::string>>> declared_methods;
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
            for (const auto& method : *methods) {
                if (!declared_methods.emplace(method.name, method.return_type,
                                              method.parameter_types).second) {
                    throw std::invalid_argument(
                        "duplicate method definition in class");
                }
            }
        }
        for (const auto& interface_descriptor : klass.interfaces) {
            type_set.insert(interface_descriptor);
        }
        if (klass.source_file.has_value()) string_set.insert(*klass.source_file);
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
          for (const auto& method : *methods) {
            if (method.name.empty() || method.return_type.empty()) throw std::invalid_argument("invalid method spec");
            constexpr std::uint32_t kNoCode = 0x0100U | 0x0400U;
            if ((method.access_flags & kNoCode) != 0U &&
                (!method.body.code_units.empty() ||
                 method.body.invoke_reference.has_value() ||
                 !method.body.invoke_references.empty() ||
                 !method.body.string_references.empty() ||
                 !method.body.references.empty() ||
                 !method.body.try_regions.empty() ||
                 method.body.debug_info.has_value())) {
                throw std::invalid_argument(
                    "native/abstract method must not contain a method body");
            }
            if ((method.access_flags & kNoCode) == 0U &&
                method.body.ins_size > method.body.registers_size) {
                throw std::invalid_argument(
                    "method ins_size exceeds registers_size");
            }
            type_set.insert(method.return_type);
            for (const auto& parameter : method.parameter_types) type_set.insert(parameter);
            ProtoKey proto{method.return_type, method.parameter_types};
            proto_set.insert(proto);
            method_keys.push_back({klass.descriptor, method.name, std::move(proto)});
            for (const auto& patch : references(method.body)) {
                std::visit([&](const auto& reference) {
                    using Reference = std::decay_t<decltype(reference)>;
                    if constexpr (std::is_same_v<Reference, std::string>) {
                        string_set.insert(reference);
                    } else if constexpr (std::is_same_v<
                                             Reference, MethodBodySpec::TypeReference>) {
                        type_set.insert(reference.descriptor);
                    } else if constexpr (std::is_same_v<
                                             Reference, MethodBodySpec::FieldReference>) {
                        add_field_reference(reference);
                    } else if constexpr (std::is_same_v<
                                             Reference, MethodBodySpec::MethodReference>) {
                        add_method_reference(reference);
                    } else if constexpr (std::is_same_v<
                                             Reference, MethodBodySpec::ProtoReference>) {
                        add_proto_reference(reference);
                    } else if constexpr (std::is_same_v<
                                             Reference, MethodHandleReference>) {
                        add_method_handle(reference);
                    } else {
                        add_call_site(reference);
                    }
                }, patch.reference);
            }
            for (const auto& region : method.body.try_regions) {
                if (region.instruction_count == 0U || region.handlers.empty()) {
                    throw std::invalid_argument("invalid DEX builder try region");
                }
                for (const auto& handler : region.handlers) {
                    if (handler.type.has_value()) type_set.insert(*handler.type);
                }
            }
            if (method.body.debug_info.has_value()) {
                const auto& debug = *method.body.debug_info;
                if (debug.parameter_names.size() != method.parameter_types.size()) {
                    throw std::invalid_argument(
                        "debug parameter name count does not match method prototype");
                }
                for (const auto& name : debug.parameter_names) {
                    if (name.has_value()) string_set.insert(*name);
                }
                for (const auto& event : debug.events) {
                    if (event.name.has_value()) string_set.insert(*event.name);
                    if (event.type.has_value()) type_set.insert(*event.type);
                    if (event.signature.has_value()) string_set.insert(*event.signature);
                    if (event.file.has_value()) string_set.insert(*event.file);
                }
            }
            collect_annotation_set(method.annotations);
            if (!method.parameter_annotations.empty() &&
                method.parameter_annotations.size() != method.parameter_types.size()) {
                throw std::invalid_argument(
                    "parameter annotation count does not match method prototype");
            }
            for (const auto& annotations : method.parameter_annotations) {
                collect_annotation_set(annotations);
            }
            string_set.insert(method.name); string_set.insert(Shorty(method));
          }
        }
        for (const auto* fields : {&klass.static_fields, &klass.instance_fields}) {
            for (const auto& field : *fields) {
                if (field.name.empty() || field.type.empty()) {
                    throw std::invalid_argument("invalid field spec");
                }
                type_set.insert(field.type);
                string_set.insert(field.name);
                field_keys.push_back({klass.descriptor, field.name, field.type});
                if (field.static_value.has_value()) {
                    collect_encoded_value(*field.static_value);
                }
                collect_annotation_set(field.annotations);
            }
        }
        collect_annotation_set(klass.annotations);
    }
    if ((!method_handle_set.empty() || !call_sites.empty()) && version_ < 38U) {
        throw std::invalid_argument(
            "method handles and call sites require DEX version 038 or newer");
    }
    string_set.insert(type_set.begin(), type_set.end());
    std::vector<std::string> strings(string_set.begin(), string_set.end());
    std::sort(strings.begin(), strings.end(), [](const auto& left, const auto& right) { return Utf16(left) < Utf16(right); });
    std::map<std::string, std::uint32_t> string_index;
    for (std::size_t i = 0; i < strings.size(); ++i) string_index.emplace(strings[i], static_cast<std::uint32_t>(i));

    std::vector<std::string> types(type_set.begin(), type_set.end());
    std::sort(types.begin(), types.end(), [&](const auto& left, const auto& right) { return string_index.at(left) < string_index.at(right); });
    std::map<std::string, std::uint16_t> type_index;
    for (std::size_t i = 0; i < types.size(); ++i) {
        if (i > 0xffffU) throw std::length_error("too many DEX types");
        type_index.emplace(types[i], static_cast<std::uint16_t>(i));
    }
    std::vector<ProtoKey> protos(proto_set.begin(), proto_set.end());
    std::sort(protos.begin(), protos.end(), [&](const auto& left, const auto& right) {
        if (type_index.at(left.return_type) != type_index.at(right.return_type)) return type_index.at(left.return_type) < type_index.at(right.return_type);
        return left.parameters < right.parameters;
    });
    std::map<ProtoKey, std::uint16_t> proto_index;
    for (std::size_t i = 0; i < protos.size(); ++i) {
        if (i > 0xffffU) throw std::length_error("too many DEX prototypes");
        proto_index.emplace(protos[i], static_cast<std::uint16_t>(i));
    }
    std::sort(method_keys.begin(), method_keys.end(), [&](const auto& left, const auto& right) {
        return std::tuple(type_index.at(left.owner), string_index.at(left.name), proto_index.at(left.proto)) <
               std::tuple(type_index.at(right.owner), string_index.at(right.name), proto_index.at(right.proto));
    });
    method_keys.erase(std::unique(method_keys.begin(), method_keys.end()), method_keys.end());
    std::map<MethodKey, std::uint32_t> method_index;
    for (std::size_t i = 0; i < method_keys.size(); ++i) {
        if (i > 0xffffU) throw std::length_error("too many DEX methods");
        method_index.emplace(method_keys[i], static_cast<std::uint32_t>(i));
    }

    std::sort(field_keys.begin(), field_keys.end(), [&](const auto& left, const auto& right) {
        return std::tuple(type_index.at(left.owner), string_index.at(left.name), type_index.at(left.type)) <
               std::tuple(type_index.at(right.owner), string_index.at(right.name), type_index.at(right.type));
    });
    field_keys.erase(std::unique(field_keys.begin(), field_keys.end()), field_keys.end());
    std::map<FieldKey, std::uint32_t> field_index;
    for (std::size_t i = 0; i < field_keys.size(); ++i) {
        if (i > 0xffffU) throw std::length_error("too many DEX fields");
        field_index.emplace(field_keys[i], static_cast<std::uint32_t>(i));
    }
    std::vector<MethodHandleKey> method_handles(method_handle_set.begin(),
                                                 method_handle_set.end());
    if (method_handles.size() > 0xffffU) {
        throw std::length_error("too many DEX method handles");
    }
    std::map<MethodHandleKey, std::uint32_t> method_handle_index;
    for (std::size_t i = 0U; i < method_handles.size(); ++i) {
        method_handle_index.emplace(method_handles[i], static_cast<std::uint32_t>(i));
    }
    if (call_sites.size() > 0xffffU) {
        throw std::length_error("too many DEX call sites");
    }

    const auto header_size = version_ == 41U ? 0x78U : 0x70U;
    std::vector<std::uint8_t> out(header_size, 0U);
    const auto string_ids_off = static_cast<std::uint32_t>(out.size());
    out.resize(out.size() + strings.size() * 4U, 0U);
    const auto type_ids_off = static_cast<std::uint32_t>(out.size());
    for (const auto& type : types) WriteU32(out, string_index.at(type));
    const auto proto_ids_off = static_cast<std::uint32_t>(out.size());
    const auto proto_patch_start = out.size();
    out.resize(out.size() + protos.size() * 12U, 0U);
    const auto field_ids_off = static_cast<std::uint32_t>(out.size());
    for (const auto& field : field_keys) {
        WriteU16(out, type_index.at(field.owner));
        WriteU16(out, type_index.at(field.type));
        WriteU32(out, string_index.at(field.name));
    }
    const auto method_ids_off = static_cast<std::uint32_t>(out.size());
    for (const auto& method : method_keys) {
        WriteU16(out, type_index.at(method.owner)); WriteU16(out, proto_index.at(method.proto)); WriteU32(out, string_index.at(method.name));
    }
    const auto class_defs_off = static_cast<std::uint32_t>(out.size());
    const auto class_patch_start = out.size();
    out.resize(out.size() + classes_.size() * 32U, 0U);
    const auto call_site_ids_off = static_cast<std::uint32_t>(out.size());
    out.resize(out.size() + call_sites.size() * 4U, 0U);
    const auto method_handles_off = static_cast<std::uint32_t>(out.size());
    for (const auto& handle : method_handles) {
        WriteU16(out, handle.handle_type);
        WriteU16(out, 0U);
        const auto member_index = std::visit([&](const auto& member) {
            using Member = std::decay_t<decltype(member)>;
            if constexpr (std::is_same_v<Member, FieldKey>) {
                return field_index.at(member);
            } else {
                return method_index.at(member);
            }
        }, handle.member);
        if (member_index > 0xffffU) {
            throw std::length_error("DEX method handle member index exceeds uint16");
        }
        WriteU16(out, static_cast<std::uint16_t>(member_index));
        WriteU16(out, 0U);
    }
    Align(out, 4U);
    const auto data_off = static_cast<std::uint32_t>(out.size());
    std::vector<MapEntry> map_entries;
    std::map<ProtoKey, std::uint32_t> parameter_offsets;
    std::map<std::string, std::uint32_t> interface_offsets;
    std::uint32_t first_type_list = 0U; std::uint32_t type_list_count = 0U;
    for (const auto& proto : protos) {
        if (proto.parameters.empty()) continue;
        Align(out, 4U);
        const auto offset = static_cast<std::uint32_t>(out.size());
        if (first_type_list == 0U) first_type_list = offset;
        ++type_list_count; parameter_offsets.emplace(proto, offset);
        WriteU32(out, static_cast<std::uint32_t>(proto.parameters.size()));
        for (const auto& parameter : proto.parameters) WriteU16(out, type_index.at(parameter));
    }
    for (const auto& klass : classes_) {
        if (klass.interfaces.empty()) continue;
        std::set<std::string> unique_interfaces(klass.interfaces.begin(), klass.interfaces.end());
        if (unique_interfaces.size() != klass.interfaces.size()) {
            throw std::invalid_argument("duplicate interface in DEX builder class");
        }
        Align(out, 4U);
        const auto offset = static_cast<std::uint32_t>(out.size());
        if (first_type_list == 0U) first_type_list = offset;
        ++type_list_count;
        interface_offsets.emplace(klass.descriptor, offset);
        WriteU32(out, static_cast<std::uint32_t>(klass.interfaces.size()));
        auto sorted_interfaces = klass.interfaces;
        std::sort(sorted_interfaces.begin(), sorted_interfaces.end(),
                  [&](const auto& left, const auto& right) {
                      return type_index.at(left) < type_index.at(right);
                  });
        for (const auto& descriptor : sorted_interfaces) {
            WriteU16(out, type_index.at(descriptor));
        }
    }
    if (type_list_count != 0U) map_entries.push_back({0x1001U, type_list_count, first_type_list});
    for (std::size_t i = 0; i < protos.size(); ++i) {
        MethodSpec temporary; temporary.return_type = protos[i].return_type; temporary.parameter_types = protos[i].parameters;
        const auto offset = proto_patch_start + i * 12U;
        PatchU32(out, offset, string_index.at(Shorty(temporary)));
        PatchU32(out, offset + 4U, type_index.at(protos[i].return_type));
        PatchU32(out, offset + 8U, protos[i].parameters.empty() ? 0U : parameter_offsets.at(protos[i]));
    }

    std::function<void(std::vector<std::uint8_t>&,
                       const EncodedAnnotationSpec&)> write_encoded_annotation;
    std::function<void(std::vector<std::uint8_t>&,
                       const EncodedValueSpec&)> write_encoded_value;
    write_encoded_annotation = [&](std::vector<std::uint8_t>& destination,
                                   const EncodedAnnotationSpec& annotation) {
        WriteUleb(destination, type_index.at(annotation.type));
        std::vector<const EncodedAnnotationElementSpec*> elements;
        elements.reserve(annotation.elements.size());
        for (const auto& element : annotation.elements) elements.push_back(&element);
        std::sort(elements.begin(), elements.end(), [&](const auto* left, const auto* right) {
            return string_index.at(left->name) < string_index.at(right->name);
        });
        WriteUleb(destination, static_cast<std::uint32_t>(elements.size()));
        std::optional<std::uint32_t> previous_name;
        for (const auto* element : elements) {
            const auto name = string_index.at(element->name);
            if (previous_name == name) {
                throw std::invalid_argument("duplicate annotation element name");
            }
            previous_name = name;
            WriteUleb(destination, name);
            write_encoded_value(destination, element->value);
        }
    };
    write_encoded_value = [&](std::vector<std::uint8_t>& destination,
                              const EncodedValueSpec& encoded) {
        const auto write_index = [&](std::uint8_t value_type, std::uint32_t index) {
            WriteEncodedScalar(destination, value_type, index,
                               MinimalUnsignedBytes(index));
        };
        const auto write_right_zero = [&](std::uint8_t value_type, auto bits) {
            using Bits = decltype(bits);
            std::uint8_t omitted = 0U;
            while (omitted + 1U < sizeof(Bits) && (bits & 0xffU) == 0U) {
                bits >>= 8U;
                ++omitted;
            }
            const auto width = static_cast<std::uint8_t>(sizeof(Bits) - omitted);
            WriteEncodedScalar(destination, value_type, bits, width);
        };
        std::visit([&](const auto& value) {
            using Value = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<Value, std::int8_t>) {
                WriteEncodedScalar(destination, 0x00U,
                    static_cast<std::uint8_t>(value), 1U);
            } else if constexpr (std::is_same_v<Value, std::int16_t>) {
                const auto width = MinimalSignedBytes(value);
                WriteEncodedScalar(destination, 0x02U,
                    static_cast<std::uint16_t>(value), width);
            } else if constexpr (std::is_same_v<Value, char16_t>) {
                const auto bits = static_cast<std::uint16_t>(value);
                WriteEncodedScalar(destination, 0x03U, bits,
                                   MinimalUnsignedBytes(bits));
            } else if constexpr (std::is_same_v<Value, std::int32_t>) {
                const auto width = MinimalSignedBytes(value);
                WriteEncodedScalar(destination, 0x04U,
                    static_cast<std::uint32_t>(value), width);
            } else if constexpr (std::is_same_v<Value, std::int64_t>) {
                const auto width = MinimalSignedBytes(value);
                WriteEncodedScalar(destination, 0x06U,
                    static_cast<std::uint64_t>(value), width);
            } else if constexpr (std::is_same_v<Value, float>) {
                write_right_zero(0x10U, std::bit_cast<std::uint32_t>(value));
            } else if constexpr (std::is_same_v<Value, double>) {
                write_right_zero(0x11U, std::bit_cast<std::uint64_t>(value));
            } else if constexpr (std::is_same_v<Value, ProtoReference>) {
                write_index(0x15U, proto_index.at(
                    {value.return_type, value.parameter_types}));
            } else if constexpr (std::is_same_v<Value, MethodHandleReference>) {
                write_index(0x16U, method_handle_index.at(ToMethodHandleKey(value)));
            } else if constexpr (std::is_same_v<Value, StringReference>) {
                write_index(0x17U, string_index.at(value.value));
            } else if constexpr (std::is_same_v<Value, TypeReference>) {
                write_index(0x18U, type_index.at(value.descriptor));
            } else if constexpr (std::is_same_v<Value, FieldReference>) {
                write_index(0x19U, field_index.at(ToFieldKey(value)));
            } else if constexpr (std::is_same_v<Value, MethodReference>) {
                write_index(0x1aU, method_index.at(ToMethodKey(value)));
            } else if constexpr (std::is_same_v<Value, EnumReference>) {
                write_index(0x1bU, field_index.at(ToFieldKey(value.field)));
            } else if constexpr (std::is_same_v<
                                     Value, std::shared_ptr<EncodedArraySpec>>) {
                destination.push_back(0x1cU);
                WriteUleb(destination,
                          static_cast<std::uint32_t>(value->values.size()));
                for (const auto& item : value->values) {
                    write_encoded_value(destination, item);
                }
            } else if constexpr (std::is_same_v<
                                     Value,
                                     std::shared_ptr<EncodedAnnotationSpec>>) {
                destination.push_back(0x1dU);
                write_encoded_annotation(destination, *value);
            } else if constexpr (std::is_same_v<Value, NullEncodedValue>) {
                destination.push_back(0x1eU);
            } else {
                destination.push_back(static_cast<std::uint8_t>(
                    0x1fU | (value ? 0x20U : 0U)));
            }
        }, encoded.value);
    };

    std::map<MethodKey, std::uint32_t> debug_offsets;
    std::uint32_t first_debug_info = 0U;
    std::uint32_t debug_info_count = 0U;
    for (const auto& klass : classes_) {
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
            for (const auto& method : *methods) {
                if (!method.body.debug_info.has_value()) continue;
                const auto& debug = *method.body.debug_info;
                const auto offset = static_cast<std::uint32_t>(out.size());
                if (first_debug_info == 0U) first_debug_info = offset;
                ++debug_info_count;
                const MethodKey key{klass.descriptor, method.name,
                                    {method.return_type, method.parameter_types}};
                if (!debug_offsets.emplace(key, offset).second) {
                    throw std::invalid_argument("duplicate method definition in class");
                }
                WriteUleb(out, debug.line_start);
                WriteUleb(out, static_cast<std::uint32_t>(debug.parameter_names.size()));
                for (const auto& name : debug.parameter_names) {
                    WriteUlebp1(out, name.has_value() ?
                        std::optional<std::uint32_t>(string_index.at(*name)) :
                        std::nullopt);
                }
                for (const auto& event : debug.events) {
                    switch (event.kind) {
                        case DebugEventKind::AdvancePc:
                            out.push_back(0x01U);
                            WriteUleb(out, event.address_difference);
                            break;
                        case DebugEventKind::AdvanceLine:
                            out.push_back(0x02U);
                            WriteSleb(out, event.line_difference);
                            break;
                        case DebugEventKind::StartLocal:
                        case DebugEventKind::StartLocalExtended:
                            out.push_back(event.kind == DebugEventKind::StartLocal ?
                                          0x03U : 0x04U);
                            WriteUleb(out, event.register_index);
                            WriteUlebp1(out, event.name.has_value() ?
                                std::optional<std::uint32_t>(
                                    string_index.at(*event.name)) : std::nullopt);
                            WriteUlebp1(out, event.type.has_value() ?
                                std::optional<std::uint32_t>(
                                    type_index.at(*event.type)) : std::nullopt);
                            if (event.kind == DebugEventKind::StartLocalExtended) {
                                WriteUlebp1(out, event.signature.has_value() ?
                                    std::optional<std::uint32_t>(
                                        string_index.at(*event.signature)) :
                                    std::nullopt);
                            }
                            break;
                        case DebugEventKind::EndLocal:
                        case DebugEventKind::RestartLocal:
                            out.push_back(event.kind == DebugEventKind::EndLocal ?
                                          0x05U : 0x06U);
                            WriteUleb(out, event.register_index);
                            break;
                        case DebugEventKind::SetPrologueEnd:
                            out.push_back(0x07U);
                            break;
                        case DebugEventKind::SetEpilogueBegin:
                            out.push_back(0x08U);
                            break;
                        case DebugEventKind::SetFile:
                            out.push_back(0x09U);
                            WriteUlebp1(out, event.file.has_value() ?
                                std::optional<std::uint32_t>(
                                    string_index.at(*event.file)) : std::nullopt);
                            break;
                        case DebugEventKind::Special:
                            if (event.special_opcode < 0x0aU) {
                                throw std::invalid_argument("invalid special debug opcode");
                            }
                            out.push_back(event.special_opcode);
                            break;
                    }
                }
                out.push_back(0x00U);
            }
        }
    }
    if (debug_info_count != 0U) {
        map_entries.push_back({0x2003U, debug_info_count, first_debug_info});
    }

    std::map<MethodKey, std::uint32_t> code_offsets;
    std::vector<CodePrefix> jumbo_promotions;
    std::uint32_t first_code = 0U; std::uint32_t code_count = 0U;
    for (const auto& klass : classes_) {
      for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
        for (const auto& method : *methods) {
            constexpr std::uint32_t kNoCode = 0x0100U | 0x0400U; // native | abstract
            if ((method.access_flags & kNoCode) != 0U) {
                if (!method.body.code_units.empty()) {
                    throw std::invalid_argument("native/abstract method must not contain code");
                }
                continue;
            }
            if (method.body.code_units.empty()) {
                throw std::invalid_argument("concrete method must contain code");
            }
            Align(out, 4U);
            const auto offset = static_cast<std::uint32_t>(out.size());
            if (first_code == 0U) first_code = offset;
            ++code_count;
            const ProtoKey proto{method.return_type, method.parameter_types};
            const MethodKey method_key{klass.descriptor, method.name, proto};
            if (!code_offsets.emplace(method_key, offset).second) {
                throw std::invalid_argument("duplicate concrete method definition in class");
            }
            if (method.body.try_regions.size() > std::numeric_limits<std::uint16_t>::max()) {
                throw std::length_error("too many DEX builder try regions");
            }
            WriteU16(out, method.body.registers_size); WriteU16(out, method.body.ins_size); WriteU16(out, method.body.outs_size);
            WriteU16(out, static_cast<std::uint16_t>(method.body.try_regions.size()));
            const auto debug = debug_offsets.find(method_key);
            WriteU32(out, debug == debug_offsets.end() ? 0U : debug->second);
            WriteU32(out, static_cast<std::uint32_t>(method.body.code_units.size()));
            const auto reference_patches = references(method.body);
            auto units = method.body.code_units;
            CodePrefix jumbo_promotion;
            jumbo_promotion.code_off = offset;
            for (const auto& patch : reference_patches) {
                if (patch.code_unit >= units.size() ||
                    (patch.wide && patch.code_unit + 1U >= units.size())) {
                    throw std::invalid_argument("symbolic reference patch exceeds code body");
                }
                const auto index = std::visit([&](const auto& reference) -> std::uint32_t {
                    using Reference = std::decay_t<decltype(reference)>;
                    if constexpr (std::is_same_v<Reference, std::string>) {
                        return string_index.at(reference);
                    } else if constexpr (std::is_same_v<Reference,
                                                        MethodBodySpec::TypeReference>) {
                        return type_index.at(reference.descriptor);
                    } else if constexpr (std::is_same_v<Reference,
                                                        MethodBodySpec::FieldReference>) {
                        return field_index.at({reference.owner, reference.name,
                                               reference.type});
                    } else if constexpr (std::is_same_v<Reference,
                                                        MethodBodySpec::MethodReference>) {
                        return method_index.at({reference.owner, reference.name,
                                                {reference.return_type,
                                                 reference.parameter_types}});
                    } else if constexpr (std::is_same_v<
                                             Reference,
                                             MethodBodySpec::ProtoReference>) {
                        return proto_index.at({reference.return_type,
                                               reference.parameter_types});
                    } else if constexpr (std::is_same_v<
                                             Reference, MethodHandleReference>) {
                        return method_handle_index.at(ToMethodHandleKey(reference));
                    } else {
                        if (!reference.values) {
                            throw std::invalid_argument("null call-site reference");
                        }
                        return call_site_ordinals.at(reference.values.get());
                    }
                }, patch.reference);
                if (!patch.wide && index > 0xffffU) {
                    const auto* string_reference =
                        std::get_if<std::string>(&patch.reference);
                    if (string_reference == nullptr || patch.code_unit == 0U) {
                        throw std::length_error(
                            "symbolic reference exceeds 16-bit instruction operand");
                    }
                    const auto instruction_offset = patch.code_unit - 1U;
                    const auto first = units.at(instruction_offset);
                    if ((first & 0xffU) != 0x1aU) {
                        throw std::length_error(
                            "only const-string may promote a 16-bit symbolic reference");
                    }
                    const auto [unused, inserted] =
                        jumbo_promotion.linear_replacements.emplace(
                            instruction_offset,
                            std::vector<std::uint16_t>{
                                static_cast<std::uint16_t>((first & 0xff00U) |
                                                           0x1bU),
                                static_cast<std::uint16_t>(index),
                                static_cast<std::uint16_t>(index >> 16U)});
                    if (!inserted) {
                        throw std::invalid_argument(
                            "duplicate const-string jumbo promotion");
                    }
                    // Keep the provisional DEX structurally valid. The complete
                    // code layout is relocated after all sections are emitted.
                    units.at(patch.code_unit) = 0U;
                    continue;
                }
                units.at(patch.code_unit) = static_cast<std::uint16_t>(index);
                if (patch.wide) {
                    units.at(patch.code_unit + 1U) =
                        static_cast<std::uint16_t>(index >> 16U);
                }
            }
            if (!jumbo_promotion.linear_replacements.empty()) {
                jumbo_promotions.push_back(std::move(jumbo_promotion));
            }
            for (const auto unit : units) WriteU16(out, unit);
            if (!method.body.try_regions.empty()) {
                if ((units.size() & 1U) != 0U) WriteU16(out, 0U);
                const auto try_items_offset = out.size();
                out.resize(out.size() + method.body.try_regions.size() * 8U, 0U);
                const auto handlers_offset = out.size();
                WriteUleb(out, static_cast<std::uint32_t>(method.body.try_regions.size()));
                for (std::size_t try_index = 0U;
                     try_index < method.body.try_regions.size(); ++try_index) {
                    const auto& region = method.body.try_regions[try_index];
                    if (region.instruction_count == 0U ||
                        region.instruction_count > 0xffffU ||
                        region.start_address >= units.size() ||
                        region.instruction_count > units.size() - region.start_address ||
                        region.handlers.empty()) {
                        throw std::invalid_argument("invalid DEX builder try region");
                    }
                    const auto handler_offset = out.size() - handlers_offset;
                    if (handler_offset > 0xffffU) {
                        throw std::length_error("DEX builder catch handler offset exceeds uint16");
                    }
                    const auto item = try_items_offset + try_index * 8U;
                    PatchU32(out, item, region.start_address);
                    out.at(item + 4U) = static_cast<std::uint8_t>(region.instruction_count);
                    out.at(item + 5U) = static_cast<std::uint8_t>(region.instruction_count >> 8U);
                    out.at(item + 6U) = static_cast<std::uint8_t>(handler_offset);
                    out.at(item + 7U) = static_cast<std::uint8_t>(handler_offset >> 8U);
                    std::size_t typed_count = 0U;
                    const MethodBodySpec::CatchHandlerSpec* catch_all = nullptr;
                    for (const auto& handler : region.handlers) {
                        if (handler.address >= units.size()) {
                            throw std::invalid_argument("DEX builder catch handler exceeds code body");
                        }
                        if (handler.type.has_value()) ++typed_count;
                        else if (catch_all == nullptr) catch_all = &handler;
                        else throw std::invalid_argument("DEX builder try has multiple catch-all handlers");
                    }
                    if (typed_count > static_cast<std::size_t>(
                                          std::numeric_limits<std::int32_t>::max())) {
                        throw std::length_error("too many DEX builder typed catches");
                    }
                    WriteSleb(out, catch_all == nullptr ?
                        static_cast<std::int32_t>(typed_count) :
                        -static_cast<std::int32_t>(typed_count));
                    for (const auto& handler : region.handlers) {
                        if (!handler.type.has_value()) continue;
                        WriteUleb(out, type_index.at(*handler.type));
                        WriteUleb(out, handler.address);
                    }
                    if (catch_all != nullptr) WriteUleb(out, catch_all->address);
                }
            }
        }
      }
    }
    if (code_count != 0U) map_entries.push_back({0x2001U, code_count, first_code});

    const auto sorted_fields = [&](const ClassSpec& klass,
                                   const std::vector<FieldSpec>& fields) {
        std::vector<const FieldSpec*> sorted;
        sorted.reserve(fields.size());
        for (const auto& field : fields) sorted.push_back(&field);
        std::sort(sorted.begin(), sorted.end(), [&](const auto* left, const auto* right) {
            return field_index.at({klass.descriptor, left->name, left->type}) <
                   field_index.at({klass.descriptor, right->name, right->type});
        });
        return sorted;
    };
    const auto sorted_methods = [&](const ClassSpec& klass,
                                    const std::vector<MethodSpec>& methods) {
        std::vector<const MethodSpec*> sorted;
        sorted.reserve(methods.size());
        for (const auto& method : methods) sorted.push_back(&method);
        std::sort(sorted.begin(), sorted.end(), [&](const auto* left, const auto* right) {
            return method_index.at({klass.descriptor, left->name,
                                    {left->return_type, left->parameter_types}}) <
                   method_index.at({klass.descriptor, right->name,
                                    {right->return_type, right->parameter_types}});
        });
        return sorted;
    };
    std::map<std::string, std::uint32_t> class_data_offsets;
    std::uint32_t first_class_data = 0U;
    for (const auto& klass : classes_) {
        const auto offset = static_cast<std::uint32_t>(out.size());
        if (first_class_data == 0U) first_class_data = offset;
        class_data_offsets.emplace(klass.descriptor, offset);
        WriteUleb(out, static_cast<std::uint32_t>(klass.static_fields.size()));
        WriteUleb(out, static_cast<std::uint32_t>(klass.instance_fields.size()));
        WriteUleb(out, static_cast<std::uint32_t>(klass.direct_methods.size()));
        WriteUleb(out, static_cast<std::uint32_t>(klass.virtual_methods.size()));
        const auto write_fields = [&](const std::vector<FieldSpec>& fields) {
            const auto sorted = sorted_fields(klass, fields);
            std::uint32_t previous = 0U;
            for (std::size_t i = 0; i < sorted.size(); ++i) {
                const auto& field = *sorted[i];
                const auto index = field_index.at({klass.descriptor, field.name, field.type});
                WriteUleb(out, i == 0U ? index : index - previous);
                WriteUleb(out, field.access_flags);
                previous = index;
            }
        };
        const auto write_methods = [&](const std::vector<MethodSpec>& methods) {
            const auto sorted = sorted_methods(klass, methods);
            std::uint32_t previous = 0U;
            for (std::size_t i = 0; i < sorted.size(); ++i) {
                const auto& method = *sorted[i];
                const MethodKey key{klass.descriptor, method.name, {method.return_type, method.parameter_types}};
                const auto index = method_index.at(key);
                const auto code = code_offsets.find(key);
                WriteUleb(out, i == 0U ? index : index - previous);
                WriteUleb(out, method.access_flags);
                WriteUleb(out, code == code_offsets.end() ? 0U : code->second);
                previous = index;
            }
        };
        write_fields(klass.static_fields);
        write_fields(klass.instance_fields);
        write_methods(klass.direct_methods);
        write_methods(klass.virtual_methods);
    }
    map_entries.push_back({0x2000U, static_cast<std::uint32_t>(classes_.size()), first_class_data});

    std::map<std::string, std::uint32_t> static_value_offsets;
    std::uint32_t first_encoded_array = 0U;
    std::uint32_t encoded_array_count = 0U;
    const auto begin_encoded_array = [&]() {
        const auto offset = static_cast<std::uint32_t>(out.size());
        if (first_encoded_array == 0U) first_encoded_array = offset;
        ++encoded_array_count;
        return offset;
    };
    for (std::size_t i = 0U; i < call_sites.size(); ++i) {
        const auto offset = begin_encoded_array();
        PatchU32(out, static_cast<std::size_t>(call_site_ids_off) + i * 4U, offset);
        WriteUleb(out, static_cast<std::uint32_t>(call_sites[i]->values.size()));
        for (const auto& value : call_sites[i]->values) write_encoded_value(out, value);
    }
    const auto default_static_value = [](std::string_view descriptor) {
        if (descriptor.empty()) throw std::invalid_argument("empty static field type");
        switch (descriptor.front()) {
            case 'Z': return EncodedValueSpec{false};
            case 'B': return EncodedValueSpec{std::int8_t{0}};
            case 'S': return EncodedValueSpec{std::int16_t{0}};
            case 'C': return EncodedValueSpec{char16_t{0}};
            case 'I': return EncodedValueSpec{std::int32_t{0}};
            case 'J': return EncodedValueSpec{std::int64_t{0}};
            case 'F': return EncodedValueSpec{0.0F};
            case 'D': return EncodedValueSpec{0.0};
            case 'L':
            case '[': return EncodedValueSpec{NullEncodedValue{}};
            default: throw std::invalid_argument("invalid static field type");
        }
    };
    for (const auto& klass : classes_) {
        const auto fields = sorted_fields(klass, klass.static_fields);
        std::size_t value_count = fields.size();
        while (value_count != 0U &&
               !fields[value_count - 1U]->static_value.has_value()) {
            --value_count;
        }
        if (value_count == 0U) continue;
        const auto offset = begin_encoded_array();
        static_value_offsets.emplace(klass.descriptor, offset);
        WriteUleb(out, static_cast<std::uint32_t>(value_count));
        for (std::size_t i = 0U; i < value_count; ++i) {
            if (fields[i]->static_value.has_value()) {
                write_encoded_value(out, *fields[i]->static_value);
            } else {
                write_encoded_value(out, default_static_value(fields[i]->type));
            }
        }
    }
    if (encoded_array_count != 0U) {
        map_entries.push_back({0x2005U, encoded_array_count, first_encoded_array});
    }

    std::vector<const std::vector<AnnotationSpec>*> annotation_sets;
    std::set<const std::vector<AnnotationSpec>*> seen_annotation_sets;
    const auto add_annotation_set = [&](const std::vector<AnnotationSpec>& annotations) {
        if (!annotations.empty() && seen_annotation_sets.insert(&annotations).second) {
            annotation_sets.push_back(&annotations);
        }
    };
    for (const auto& klass : classes_) {
        add_annotation_set(klass.annotations);
        for (const auto* fields : {&klass.static_fields, &klass.instance_fields}) {
            for (const auto& field : *fields) add_annotation_set(field.annotations);
        }
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
            for (const auto& method : *methods) {
                add_annotation_set(method.annotations);
                for (const auto& annotations : method.parameter_annotations) {
                    add_annotation_set(annotations);
                }
            }
        }
    }
    std::map<const AnnotationSpec*, std::uint32_t> annotation_item_offsets;
    std::uint32_t first_annotation_item = 0U;
    std::uint32_t annotation_item_count = 0U;
    for (const auto* annotations : annotation_sets) {
        for (const auto& annotation : *annotations) {
            const auto offset = static_cast<std::uint32_t>(out.size());
            if (first_annotation_item == 0U) first_annotation_item = offset;
            ++annotation_item_count;
            annotation_item_offsets.emplace(&annotation, offset);
            out.push_back(annotation.visibility);
            write_encoded_annotation(out, annotation.annotation);
        }
    }
    if (annotation_item_count != 0U) {
        map_entries.push_back({0x2004U, annotation_item_count,
                               first_annotation_item});
    }
    std::map<const std::vector<AnnotationSpec>*, std::uint32_t>
        annotation_set_offsets;
    std::uint32_t first_annotation_set = 0U;
    for (const auto* annotations : annotation_sets) {
        Align(out, 4U);
        const auto offset = static_cast<std::uint32_t>(out.size());
        if (first_annotation_set == 0U) first_annotation_set = offset;
        annotation_set_offsets.emplace(annotations, offset);
        std::vector<const AnnotationSpec*> sorted;
        sorted.reserve(annotations->size());
        for (const auto& annotation : *annotations) sorted.push_back(&annotation);
        std::sort(sorted.begin(), sorted.end(), [&](const auto* left, const auto* right) {
            return type_index.at(left->annotation.type) <
                   type_index.at(right->annotation.type);
        });
        WriteU32(out, static_cast<std::uint32_t>(sorted.size()));
        for (const auto* annotation : sorted) {
            WriteU32(out, annotation_item_offsets.at(annotation));
        }
    }
    if (!annotation_sets.empty()) {
        map_entries.push_back({0x1003U,
                               static_cast<std::uint32_t>(annotation_sets.size()),
                               first_annotation_set});
    }

    std::map<const MethodSpec*, std::uint32_t> parameter_annotation_offsets;
    std::uint32_t first_annotation_set_ref = 0U;
    std::uint32_t annotation_set_ref_count = 0U;
    for (const auto& klass : classes_) {
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
            for (const auto& method : *methods) {
                if (method.parameter_annotations.empty()) continue;
                Align(out, 4U);
                const auto offset = static_cast<std::uint32_t>(out.size());
                if (first_annotation_set_ref == 0U) first_annotation_set_ref = offset;
                ++annotation_set_ref_count;
                parameter_annotation_offsets.emplace(&method, offset);
                WriteU32(out, static_cast<std::uint32_t>(
                    method.parameter_annotations.size()));
                for (const auto& annotations : method.parameter_annotations) {
                    WriteU32(out, annotations.empty() ? 0U :
                        annotation_set_offsets.at(&annotations));
                }
            }
        }
    }
    if (annotation_set_ref_count != 0U) {
        map_entries.push_back({0x1002U, annotation_set_ref_count,
                               first_annotation_set_ref});
    }

    std::map<std::string, std::uint32_t> annotation_directory_offsets;
    std::uint32_t first_annotation_directory = 0U;
    std::uint32_t annotation_directory_count = 0U;
    for (const auto& klass : classes_) {
        std::vector<std::pair<std::uint32_t, std::uint32_t>> field_annotations;
        std::vector<std::pair<std::uint32_t, std::uint32_t>> method_annotations;
        std::vector<std::pair<std::uint32_t, std::uint32_t>> parameter_annotations;
        for (const auto* fields : {&klass.static_fields, &klass.instance_fields}) {
            for (const auto& field : *fields) {
                if (field.annotations.empty()) continue;
                field_annotations.emplace_back(
                    field_index.at({klass.descriptor, field.name, field.type}),
                    annotation_set_offsets.at(&field.annotations));
            }
        }
        for (const auto* methods : {&klass.direct_methods, &klass.virtual_methods}) {
            for (const auto& method : *methods) {
                const auto index = method_index.at(
                    {klass.descriptor, method.name,
                     {method.return_type, method.parameter_types}});
                if (!method.annotations.empty()) {
                    method_annotations.emplace_back(
                        index, annotation_set_offsets.at(&method.annotations));
                }
                if (!method.parameter_annotations.empty()) {
                    parameter_annotations.emplace_back(
                        index, parameter_annotation_offsets.at(&method));
                }
            }
        }
        if (klass.annotations.empty() && field_annotations.empty() &&
            method_annotations.empty() && parameter_annotations.empty()) {
            continue;
        }
        std::sort(field_annotations.begin(), field_annotations.end());
        std::sort(method_annotations.begin(), method_annotations.end());
        std::sort(parameter_annotations.begin(), parameter_annotations.end());
        Align(out, 4U);
        const auto offset = static_cast<std::uint32_t>(out.size());
        if (first_annotation_directory == 0U) first_annotation_directory = offset;
        ++annotation_directory_count;
        annotation_directory_offsets.emplace(klass.descriptor, offset);
        WriteU32(out, klass.annotations.empty() ? 0U :
            annotation_set_offsets.at(&klass.annotations));
        WriteU32(out, static_cast<std::uint32_t>(field_annotations.size()));
        WriteU32(out, static_cast<std::uint32_t>(method_annotations.size()));
        WriteU32(out, static_cast<std::uint32_t>(parameter_annotations.size()));
        const auto write_annotation_entries = [&](const auto& entries) {
            for (const auto& [index, annotations_offset] : entries) {
                WriteU32(out, index);
                WriteU32(out, annotations_offset);
            }
        };
        write_annotation_entries(field_annotations);
        write_annotation_entries(method_annotations);
        write_annotation_entries(parameter_annotations);
    }
    if (annotation_directory_count != 0U) {
        map_entries.push_back({0x2006U, annotation_directory_count,
                               first_annotation_directory});
    }

    const auto first_string_data = static_cast<std::uint32_t>(out.size());
    for (std::size_t i = 0; i < strings.size(); ++i) {
        PatchU32(out, string_ids_off + i * 4U, static_cast<std::uint32_t>(out.size()));
        const auto utf16 = Utf16(strings[i]); WriteUleb(out, static_cast<std::uint32_t>(utf16.size()));
        const auto encoded = Mutf8(strings[i]); out.insert(out.end(), encoded.begin(), encoded.end()); out.push_back(0U);
    }
    map_entries.push_back({0x2002U, static_cast<std::uint32_t>(strings.size()), first_string_data});

    std::vector<const ClassSpec*> sorted_classes;
    std::map<std::string, const ClassSpec*> defined_classes;
    std::vector<const ClassSpec*> class_roots;
    for (const auto& klass : classes_) {
        defined_classes.emplace(klass.descriptor, &klass);
        class_roots.push_back(&klass);
    }
    std::sort(class_roots.begin(), class_roots.end(), [&](const auto* left,
                                                          const auto* right) {
        return type_index.at(left->descriptor) < type_index.at(right->descriptor);
    });
    std::map<std::string, std::uint8_t> class_state;
    std::function<void(const ClassSpec&)> visit_class;
    visit_class = [&](const ClassSpec& klass) {
        auto& state = class_state[klass.descriptor];
        if (state == 2U) return;
        if (state == 1U) {
            throw std::invalid_argument("cyclic class hierarchy in DEX builder");
        }
        state = 1U;
        const auto visit_dependency = [&](const std::string& descriptor) {
            const auto found = defined_classes.find(descriptor);
            if (found != defined_classes.end()) visit_class(*found->second);
        };
        if (klass.superclass.has_value()) visit_dependency(*klass.superclass);
        auto interfaces = klass.interfaces;
        std::sort(interfaces.begin(), interfaces.end(), [&](const auto& left,
                                                            const auto& right) {
            return type_index.at(left) < type_index.at(right);
        });
        for (const auto& interface_type : interfaces) {
            visit_dependency(interface_type);
        }
        state = 2U;
        sorted_classes.push_back(&klass);
    };
    for (const auto* klass : class_roots) visit_class(*klass);
    for (std::size_t i = 0; i < sorted_classes.size(); ++i) {
        const auto& klass = *sorted_classes[i]; const auto offset = class_patch_start + i * 32U;
        PatchU32(out, offset, type_index.at(klass.descriptor)); PatchU32(out, offset + 4U, klass.access_flags);
        PatchU32(out, offset + 8U, klass.superclass.has_value() ?
            type_index.at(*klass.superclass) : kNoIndex);
        PatchU32(out, offset + 12U, klass.interfaces.empty() ? 0U : interface_offsets.at(klass.descriptor));
        PatchU32(out, offset + 16U, klass.source_file.has_value() ?
            string_index.at(*klass.source_file) : kNoIndex);
        const auto annotations = annotation_directory_offsets.find(klass.descriptor);
        PatchU32(out, offset + 20U, annotations == annotation_directory_offsets.end() ?
            0U : annotations->second);
        PatchU32(out, offset + 24U, class_data_offsets.at(klass.descriptor));
        const auto static_values = static_value_offsets.find(klass.descriptor);
        PatchU32(out, offset + 28U, static_values == static_value_offsets.end() ?
            0U : static_values->second);
    }

    Align(out, 4U);
    const auto map_off = static_cast<std::uint32_t>(out.size());
    map_entries.insert(map_entries.begin(), {
        {0x0000U, 1U, 0U}, {0x0001U, static_cast<std::uint32_t>(strings.size()), string_ids_off},
        {0x0002U, static_cast<std::uint32_t>(types.size()), type_ids_off},
        {0x0006U, static_cast<std::uint32_t>(classes_.size()), class_defs_off},
    });
    if (!protos.empty()) {
        map_entries.push_back({0x0003U, static_cast<std::uint32_t>(protos.size()),
                               proto_ids_off});
    }
    if (!method_keys.empty()) {
        map_entries.push_back({0x0005U, static_cast<std::uint32_t>(method_keys.size()),
                               method_ids_off});
    }
    if (!field_keys.empty()) {
        map_entries.push_back({0x0004U, static_cast<std::uint32_t>(field_keys.size()), field_ids_off});
    }
    if (!call_sites.empty()) {
        map_entries.push_back({0x0007U, static_cast<std::uint32_t>(call_sites.size()),
                               call_site_ids_off});
    }
    if (!method_handles.empty()) {
        map_entries.push_back({0x0008U,
                               static_cast<std::uint32_t>(method_handles.size()),
                               method_handles_off});
    }
    map_entries.push_back({0x1000U, 1U, map_off});
    std::sort(map_entries.begin(), map_entries.end(), [](const auto& left, const auto& right) { return left.offset < right.offset; });
    WriteU32(out, static_cast<std::uint32_t>(map_entries.size()));
    for (const auto& entry : map_entries) { WriteU16(out, entry.type); WriteU16(out, 0U); WriteU32(out, entry.count); WriteU32(out, entry.offset); }

    out[0] = 'd'; out[1] = 'e'; out[2] = 'x'; out[3] = '\n';
    out[4] = static_cast<std::uint8_t>('0' + version_ / 100U);
    out[5] = static_cast<std::uint8_t>('0' + (version_ / 10U) % 10U);
    out[6] = static_cast<std::uint8_t>('0' + version_ % 10U); out[7] = 0U;
    PatchU32(out, 0x20U, static_cast<std::uint32_t>(out.size())); PatchU32(out, 0x24U, header_size); PatchU32(out, 0x28U, 0x12345678U);
    PatchU32(out, 0x34U, map_off); PatchU32(out, 0x38U, static_cast<std::uint32_t>(strings.size())); PatchU32(out, 0x3cU, string_ids_off);
    PatchU32(out, 0x40U, static_cast<std::uint32_t>(types.size()));
    PatchU32(out, 0x44U, types.empty() ? 0U : type_ids_off);
    PatchU32(out, 0x48U, static_cast<std::uint32_t>(protos.size()));
    PatchU32(out, 0x4cU, protos.empty() ? 0U : proto_ids_off);
    PatchU32(out, 0x50U, static_cast<std::uint32_t>(field_keys.size()));
    PatchU32(out, 0x54U, field_keys.empty() ? 0U : field_ids_off);
    PatchU32(out, 0x58U, static_cast<std::uint32_t>(method_keys.size()));
    PatchU32(out, 0x5cU, method_keys.empty() ? 0U : method_ids_off);
    PatchU32(out, 0x60U, static_cast<std::uint32_t>(classes_.size())); PatchU32(out, 0x64U, class_defs_off);
    PatchU32(out, 0x68U, static_cast<std::uint32_t>(out.size()) - data_off); PatchU32(out, 0x6cU, data_off);
    if (version_ == 41U) {
        PatchU32(out, 0x70U, static_cast<std::uint32_t>(out.size()));
        PatchU32(out, 0x74U, 0U);
    }
    UpdateDexChecksums(out);
    if (jumbo_promotions.empty() && addresses == nullptr) return out;
    return RewriteCodePrefixes(DexFile::Parse(out), jumbo_promotions, addresses);
}

} // namespace birch::dex
