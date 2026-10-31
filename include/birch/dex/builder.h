#pragma once

#include "birch/dex/code_layout.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace birch::dex {

struct StringReference {
    std::string value;
};

struct TypeReference {
    std::string descriptor;
};

struct FieldReference {
    std::string owner;
    std::string name;
    std::string type;
};

struct MethodReference {
    std::string owner;
    std::string name;
    std::string return_type;
    std::vector<std::string> parameter_types;
};

struct ProtoReference {
    std::string return_type;
    std::vector<std::string> parameter_types;
};

struct EnumReference {
    FieldReference field;
};

struct MethodHandleReference {
    std::uint16_t handle_type{};
    std::variant<FieldReference, MethodReference> member;
};

struct EncodedArraySpec;
struct EncodedAnnotationSpec;

struct NullEncodedValue final {};

struct EncodedValueSpec {
    using Value = std::variant<
        std::int8_t, std::int16_t, char16_t, std::int32_t, std::int64_t,
        float, double, ProtoReference, MethodHandleReference, StringReference,
        TypeReference, FieldReference, MethodReference, EnumReference,
        std::shared_ptr<EncodedArraySpec>, std::shared_ptr<EncodedAnnotationSpec>,
        NullEncodedValue, bool>;
    Value value;
};

struct EncodedArraySpec {
    std::vector<EncodedValueSpec> values;
};

struct EncodedAnnotationElementSpec {
    std::string name;
    EncodedValueSpec value;
};

struct EncodedAnnotationSpec {
    std::string type;
    std::vector<EncodedAnnotationElementSpec> elements;
};

struct AnnotationSpec {
    std::uint8_t visibility{};
    EncodedAnnotationSpec annotation;
};

enum class DebugEventKind : std::uint8_t {
    AdvancePc,
    AdvanceLine,
    StartLocal,
    StartLocalExtended,
    EndLocal,
    RestartLocal,
    SetPrologueEnd,
    SetEpilogueBegin,
    SetFile,
    Special,
};

struct DebugEventSpec {
    DebugEventKind kind{DebugEventKind::Special};
    std::uint32_t register_index{};
    std::uint32_t address_difference{};
    std::int32_t line_difference{};
    std::optional<std::string> name;
    std::optional<std::string> type;
    std::optional<std::string> signature;
    std::optional<std::string> file;
    std::uint8_t special_opcode{};
};

struct DebugInfoSpec {
    std::uint32_t line_start{};
    std::vector<std::optional<std::string>> parameter_names;
    std::vector<DebugEventSpec> events;
};

struct CallSiteReference {
    std::shared_ptr<EncodedArraySpec> values;
};

struct MethodBodySpec {
    std::uint16_t registers_size{};
    std::uint16_t ins_size{};
    std::uint16_t outs_size{};
    std::vector<std::uint16_t> code_units;
    using MethodReference = birch::dex::MethodReference;
    struct MethodReferencePatch {
        MethodReference reference;
        std::uint32_t code_unit{};
    };
    struct StringReferencePatch {
        std::string value;
        std::uint32_t code_unit{};
    };
    using TypeReference = birch::dex::TypeReference;
    using FieldReference = birch::dex::FieldReference;
    using ProtoReference = birch::dex::ProtoReference;
    using SymbolicReference = std::variant<std::string, TypeReference, FieldReference,
                                           MethodReference, ProtoReference,
                                           MethodHandleReference, CallSiteReference>;
    struct ReferencePatch {
        SymbolicReference reference;
        std::uint32_t code_unit{};
        bool wide{};
    };
    struct CatchHandlerSpec {
        std::optional<std::string> type;
        std::uint32_t address{};
    };
    struct TryRegionSpec {
        std::uint32_t start_address{};
        std::uint32_t instruction_count{};
        std::vector<CatchHandlerSpec> handlers;
    };
    std::optional<MethodReference> invoke_reference;
    std::uint32_t invoke_reference_unit{1U};
    std::vector<MethodReferencePatch> invoke_references;
    std::vector<StringReferencePatch> string_references;
    std::vector<ReferencePatch> references;
    std::vector<TryRegionSpec> try_regions;
    std::optional<DebugInfoSpec> debug_info;
};

struct MethodSpec {
    std::string name;
    std::string return_type{"V"};
    std::vector<std::string> parameter_types;
    std::uint32_t access_flags{0x0009U}; // public static
    MethodBodySpec body;
    std::vector<AnnotationSpec> annotations;
    std::vector<std::vector<AnnotationSpec>> parameter_annotations;
};

struct FieldSpec {
    std::string name;
    std::string type;
    std::uint32_t access_flags{};
    std::optional<EncodedValueSpec> static_value;
    std::vector<AnnotationSpec> annotations;
};

struct ClassSpec {
    std::string descriptor;
    std::optional<std::string> superclass{"Ljava/lang/Object;"};
    std::uint32_t access_flags{0x0011U}; // public final
    std::vector<MethodSpec> direct_methods;
    std::vector<MethodSpec> virtual_methods;
    std::vector<FieldSpec> static_fields;
    std::vector<FieldSpec> instance_fields;
    std::vector<std::string> interfaces;
    std::optional<std::string> source_file;
    std::vector<AnnotationSpec> annotations;
};

class DexBuilder final {
public:
    explicit DexBuilder(std::uint32_t version = 38U);
    void AddClass(ClassSpec spec);
    void AddString(std::string value);
    [[nodiscard]] std::vector<std::uint8_t> Build(CodeAddressMaps* addresses = nullptr) const;

private:
    std::uint32_t version_{};
    std::vector<ClassSpec> classes_;
    std::set<std::string, std::less<>> class_descriptors_;
    std::vector<std::string> extra_strings_;
};

} // namespace birch::dex
