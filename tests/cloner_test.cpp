#include "birch/dex/builder.h"
#include "birch/dex/cloner.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/program.h"
#include "birch/dex/verifier.h"

#include <cassert>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

birch::dex::EncodedValueSpec StringValue(std::string value) {
    return {birch::dex::StringReference{std::move(value)}};
}

birch::dex::AnnotationSpec Annotation(std::string value) {
    birch::dex::EncodedAnnotationSpec annotation;
    annotation.type = "Ltest/Annotation;";
    annotation.elements.push_back({"value", StringValue(std::move(value))});
    return {1U, std::move(annotation)};
}

} // namespace

int main() {
    using namespace birch::dex;

    DexBuilder builder(38U);
    ClassSpec rich;
    rich.descriptor = "Ltest/Rich;";
    rich.source_file = "Rich.java";
    rich.annotations.push_back(Annotation("class"));

    FieldSpec answer;
    answer.name = "answer";
    answer.type = "I";
    answer.access_flags = 0x0019U;
    answer.static_value = EncodedValueSpec{std::int32_t{42}};
    answer.annotations.push_back(Annotation("field"));
    rich.static_fields.push_back(std::move(answer));

    FieldSpec text;
    text.name = "text";
    text.type = "Ljava/lang/String;";
    text.access_flags = 0x0019U;
    text.static_value = StringValue("hello");
    rich.static_fields.push_back(std::move(text));

    MethodReference gc{"Ljava/lang/System;", "gc", "V", {}};
    MethodHandleReference handle{4U, gc};
    auto call_site = std::make_shared<EncodedArraySpec>();
    call_site->values = {
        EncodedValueSpec{handle},
        StringValue("bootstrapName"),
        EncodedValueSpec{ProtoReference{"V", {}}},
    };

    MethodSpec method;
    method.name = "call";
    method.parameter_types = {"I"};
    method.body.registers_size = 2U;
    method.body.ins_size = 1U;
    method.body.code_units = {
        0x00feU, 0U,
        0x00fcU, 0U, 0U,
        0x000eU,
    };
    method.body.references = {
        {handle, 1U, false},
        {CallSiteReference{call_site}, 3U, false},
    };
    DebugInfoSpec debug;
    debug.line_start = 10U;
    debug.parameter_names = {std::string("input")};
    DebugEventSpec advance;
    advance.kind = DebugEventKind::AdvancePc;
    advance.address_difference = 2U;
    debug.events.push_back(advance);
    DebugEventSpec position;
    position.kind = DebugEventKind::Special;
    position.special_opcode = 0x0eU;
    debug.events.push_back(position);
    method.body.debug_info = std::move(debug);
    method.annotations.push_back(Annotation("method"));
    method.parameter_annotations = {{Annotation("parameter")}};
    rich.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(rich));

    ClassSpec simple;
    simple.descriptor = "Ltest/Simple;";
    simple.direct_methods.push_back(
        {"run", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(simple));

    const auto source_bytes = builder.Build();
    const auto source = DexFile::Parse(source_bytes);
    assert(VerifyDex(source, VerificationLevel::Full).ok);
    assert(source.call_sites().size() == 1U);
    assert(source.method_handles().size() == 1U);
    const auto rich_class = source.descriptor(source.classes().front().class_idx) ==
                                    "Ltest/Rich;" ? 0U : 1U;
    assert(source.classes().at(rich_class).annotations_off != 0U);
    assert(source.classes().at(rich_class).static_values_off != 0U);

    DexClassCloner cloner(source);
    const auto cloned_spec = cloner.Clone(rich_class);
    assert(cloned_spec.descriptor == "Ltest/Rich;");
    assert(cloned_spec.source_file == "Rich.java");
    assert(cloned_spec.annotations.size() == 1U);
    assert(cloned_spec.static_fields.size() == 2U);
    assert(std::get<std::int32_t>(
               cloned_spec.static_fields.front().static_value->value) == 42);
    assert(std::get<StringReference>(
               cloned_spec.static_fields.back().static_value->value).value == "hello");
    assert(cloned_spec.direct_methods.front().body.debug_info.has_value());
    assert(cloned_spec.direct_methods.front().body.debug_info->parameter_names.front() ==
           "input");
    assert(cloned_spec.direct_methods.front().annotations.size() == 1U);
    assert(cloned_spec.direct_methods.front().parameter_annotations.size() == 1U);

    const auto program = DexProgram::Parse({{"classes.dex", source_bytes}});
    const auto handles = program.classes();
    const auto rebuilt = BuildDexPartition(
        program, std::span<const ClassHandle>(handles.data(), handles.size()));
    const auto rebuilt_dex = DexFile::Parse(rebuilt.bytes);
    assert(VerifyDex(rebuilt_dex, VerificationLevel::Full).ok);
    assert(rebuilt_dex.call_sites().size() == 1U);
    assert(rebuilt_dex.method_handles().size() == 1U);

    RepartitionOptions options;
    options.partition.limits.strings = static_cast<std::uint32_t>(
        source.strings().size() - 1U);
    const auto partitions = RepartitionProgram(program, options);
    assert(partitions.size() == 2U);
    assert(partitions.front().classes.size() == 1U);
    assert(partitions.back().classes.size() == 1U);
    for (const auto& partition : partitions) {
        assert(VerifyDex(DexFile::Parse(partition.bytes),
                         VerificationLevel::Full).ok);
    }
    return 0;
}
