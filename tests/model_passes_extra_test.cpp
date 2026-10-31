#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"
#include "birch/guard/model_lowering.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>

namespace {

birch::guard::GuardConfig Config(std::string_view pass) {
    return birch::guard::GuardConfig::Parse(
        std::string(R"json({
          "seed": 912345,
          "scope": {"protect": [{"pattern": "Lextra/**;"}], "keep": []},
          "passes": {
        )json") +
        "\"" + std::string(pass) +
        R"json(": {"enabled": true, "intensity": 1.0}
          }
        })json");
}

birch::guard::GuardConfig StackedStructureConfig() {
    return birch::guard::GuardConfig::Parse(R"json({
      "seed": 912345,
      "scope": {"protect": [{"pattern": "Lextra/**;"}], "keep": []},
      "passes": {
        "structure.method_outlining": {"enabled": true, "intensity": 1.0},
        "structure.method_splitting": {"enabled": true, "intensity": 1.0},
        "structure.proxy_stubs": {"enabled": true, "intensity": 1.0},
        "cfg.tail_recursion": {"enabled": true, "intensity": 1.0}
      }
    })json");
}

birch::guard::GuardConfig SplitReflectionConfig() {
    return birch::guard::GuardConfig::Parse(R"json({
      "seed": 912345,
      "scope": {"protect": [{"pattern": "Lextra/**;"}], "keep": []},
      "passes": {
        "structure.class_splitting": {"enabled": true, "intensity": 1.0},
        "reflection.indirect_targets": {"enabled": true, "intensity": 1.0}
      }
    })json");
}

birch::dex::MethodSpec ConstantMethod(std::string name, std::string return_type = "I") {
    birch::dex::MethodSpec method;
    method.name = std::move(name);
    method.return_type = std::move(return_type);
    method.access_flags = 0x0009U;
    method.body.registers_size = 1U;
    method.body.code_units = {0x0012U, 0x000fU};
    return method;
}

birch::dex::MethodSpec LoopMethod(std::string name) {
    birch::dex::MethodSpec method;
    method.name = std::move(name);
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 1U;
    method.body.ins_size = 1U;
    method.body.code_units = {
        0x003dU, 6U,      // if-lez p0, return
        0x00d8U, 0xff00U, // add-int/lit8 p0, p0, -1
        0x0029U, 0xfffcU, // goto/16 loop header
        0x000fU,          // return p0
    };
    return method;
}

} // namespace

int main() {
    using namespace birch;

    // Parameter-return accessors are inlined by replacing invoke/move-result
    // with a direct typed register move.
    dex::DexBuilder inline_builder(38U);
    dex::ClassSpec inline_class;
    inline_class.descriptor = "Lextra/Inline;";
    dex::MethodSpec identity;
    identity.name = "identity";
    identity.return_type = "I";
    identity.parameter_types = {"I"};
    identity.access_flags = 0x000aU; // private static
    identity.body.registers_size = 1U;
    identity.body.ins_size = 1U;
    identity.body.code_units = {0x000fU}; // return v0
    inline_class.direct_methods.push_back(identity);
    dex::MethodSpec caller;
    caller.name = "caller";
    caller.return_type = "I";
    caller.parameter_types = {"I"};
    caller.access_flags = 0x0009U;
    caller.body.registers_size = 1U;
    caller.body.ins_size = 1U;
    caller.body.outs_size = 1U;
    caller.body.code_units = {0x1071U, 0U, 0U, 0x000aU, 0x000fU};
    caller.body.references.push_back({
        dex::MethodReference{"Lextra/Inline;", "identity", "I", {"I"}},
        1U, false});
    inline_class.direct_methods.push_back(std::move(caller));
    inline_builder.AddClass(std::move(inline_class));
    const auto inline_source = dex::DexFile::Parse(inline_builder.Build());
    const auto inlined = guard::DexModelLowering(
        Config("structure.method_inlining")).Apply(inline_source);
    assert(inlined.inlined_calls == 1U);
    const auto inline_dex = dex::DexFile::Parse(inlined.bytes);
    dex::VerifyDexOrThrow(inline_dex, dex::VerificationLevel::Full);
    const auto& inline_data = inline_dex.class_data(0U);
    const auto caller_method = std::find_if(
        inline_data.direct_methods.begin(), inline_data.direct_methods.end(),
        [&](const auto& encoded_method) {
            return inline_dex.string(
                inline_dex.methods().at(encoded_method.method_idx).name_idx) ==
                "caller";
        });
    assert(caller_method != inline_data.direct_methods.end());
    const auto caller_code = dex::DecodeCodeItem(
        inline_dex, caller_method->code_off);
    assert(caller_code.instructions.front().opcode == 0x01U);
    assert(std::none_of(caller_code.instructions.begin(),
                        caller_code.instructions.end(),
                        [](const auto& instruction) {
                            return instruction.opcode == 0x71U;
                        }));

    // Small arithmetic leaf methods are inlined as typed literal operations,
    // preserving the callsite width without leaving executable nop padding.
    dex::DexBuilder arithmetic_inline_builder(38U);
    dex::ClassSpec arithmetic_inline_class;
    arithmetic_inline_class.descriptor = "Lextra/ArithmeticInline;";
    dex::MethodSpec arithmetic_leaf;
    arithmetic_leaf.name = "mix";
    arithmetic_leaf.return_type = "I";
    arithmetic_leaf.parameter_types = {"I"};
    arithmetic_leaf.access_flags = 0x100aU; // private static synthetic
    arithmetic_leaf.body.registers_size = 1U;
    arithmetic_leaf.body.ins_size = 1U;
    arithmetic_leaf.body.code_units = {
        0x00dfU, 0x5d00U, // xor-int/lit8 v0, v0, #0x5d
        0x000fU};
    arithmetic_inline_class.direct_methods.push_back(
        std::move(arithmetic_leaf));
    dex::MethodSpec arithmetic_caller;
    arithmetic_caller.name = "caller";
    arithmetic_caller.return_type = "I";
    arithmetic_caller.parameter_types = {"I"};
    arithmetic_caller.access_flags = 0x0009U;
    arithmetic_caller.body.registers_size = 1U;
    arithmetic_caller.body.ins_size = 1U;
    arithmetic_caller.body.outs_size = 1U;
    arithmetic_caller.body.code_units = {
        0x1071U, 0U, 0U, 0x000aU, 0x000fU};
    arithmetic_caller.body.references.push_back({
        dex::MethodReference{"Lextra/ArithmeticInline;", "mix", "I", {"I"}},
        1U, false});
    arithmetic_inline_class.direct_methods.push_back(
        std::move(arithmetic_caller));
    arithmetic_inline_builder.AddClass(std::move(arithmetic_inline_class));
    const auto arithmetic_inlined = guard::DexModelLowering(
        Config("structure.method_inlining")).Apply(
            dex::DexFile::Parse(arithmetic_inline_builder.Build()));
    assert(arithmetic_inlined.inlined_calls == 1U);
    const auto arithmetic_inline_dex = dex::DexFile::Parse(
        arithmetic_inlined.bytes);
    dex::VerifyDexOrThrow(arithmetic_inline_dex,
                          dex::VerificationLevel::Full);
    const auto& arithmetic_data = arithmetic_inline_dex.class_data(0U);
    const auto arithmetic_caller_method = std::find_if(
        arithmetic_data.direct_methods.begin(), arithmetic_data.direct_methods.end(),
        [&](const auto& encoded_method) {
            return arithmetic_inline_dex.string(
                arithmetic_inline_dex.methods().at(
                    encoded_method.method_idx).name_idx) == "caller";
        });
    assert(arithmetic_caller_method != arithmetic_data.direct_methods.end());
    const auto arithmetic_code = dex::DecodeCodeItem(
        arithmetic_inline_dex, arithmetic_caller_method->code_off);
    assert(arithmetic_code.instructions.front().opcode == 0xdfU);
    assert(std::none_of(arithmetic_code.instructions.begin(),
                        arithmetic_code.instructions.end(),
                        [](const auto& instruction) {
                            return instruction.opcode == 0x00U ||
                                   instruction.opcode == 0x71U;
                        }));

    // Outlining supports production signatures through invoke-static/range
    // instead of silently skipping methods with more than five input words.
    dex::DexBuilder range_builder(38U);
    dex::ClassSpec range_class;
    range_class.descriptor = "Lextra/Range;";
    dex::MethodSpec range_method;
    range_method.name = "many";
    range_method.return_type = "I";
    range_method.parameter_types = {"I", "I", "I", "I", "I", "I"};
    range_method.access_flags = 0x0009U;
    range_method.body.registers_size = 6U;
    range_method.body.ins_size = 6U;
    range_method.body.code_units = {0x000fU};
    range_class.direct_methods.push_back(std::move(range_method));
    range_builder.AddClass(std::move(range_class));
    const auto range_source = dex::DexFile::Parse(range_builder.Build());
    const auto ranged = guard::DexModelLowering(
        Config("structure.method_outlining")).Apply(range_source);
    assert(ranged.outlined_methods == 1U);
    const auto range_dex = dex::DexFile::Parse(ranged.bytes);
    dex::VerifyDexOrThrow(range_dex, dex::VerificationLevel::Full);
    const auto& range_data = range_dex.class_data(0U);
    const auto range_method_entry = std::find_if(
        range_data.direct_methods.begin(), range_data.direct_methods.end(),
        [&](const auto& encoded) {
            return range_dex.string(
                range_dex.methods().at(encoded.method_idx).name_idx) == "many";
        });
    assert(range_method_entry != range_data.direct_methods.end());
    const auto range_entry = dex::DecodeCodeItem(
        range_dex, range_method_entry->code_off);
    assert(range_entry.instructions.front().opcode == 0x77U);

    // Full strength composes the structural layers; enabling every pass must
    // not degrade to choosing one random wrapper.
    dex::DexBuilder stacked_builder(38U);
    dex::ClassSpec stacked_class;
    stacked_class.descriptor = "Lextra/Stacked;";
    stacked_class.direct_methods.push_back(LoopMethod("work"));
    stacked_builder.AddClass(std::move(stacked_class));
    const auto stacked_source = dex::DexFile::Parse(stacked_builder.Build());
    const auto stacked = guard::DexModelLowering(
        StackedStructureConfig()).Apply(stacked_source);
    assert(stacked.outlined_methods == 1U);
    assert(stacked.split_methods == 1U);
    assert(stacked.proxy_methods == 1U);
    assert(stacked.tail_recursive_methods == 1U);
    const auto stacked_dex = dex::DexFile::Parse(stacked.bytes);
    dex::VerifyDexOrThrow(stacked_dex, dex::VerificationLevel::Full);
    assert(stacked_dex.classes().size() == 2U);

    // Reflection redirection precedes class splitting. Otherwise the direct
    // Class.forName edge is moved into a generated companion and escapes the
    // class-local indirect-target pass.
    dex::DexBuilder split_reflection_builder(38U);
    dex::ClassSpec split_reflection_class;
    split_reflection_class.descriptor = "Lextra/SplitReflection;";
    dex::MethodSpec split_reflection_method;
    split_reflection_method.name = "load";
    split_reflection_method.return_type = "Ljava/lang/Class;";
    split_reflection_method.access_flags = 0x0009U;
    split_reflection_method.body.registers_size = 1U;
    split_reflection_method.body.outs_size = 1U;
    split_reflection_method.body.code_units = {
        0x001aU, 0U,             // const-string v0, class name
        0x1071U, 0U, 0x0000U,   // invoke-static {v0}, Class.forName
        0x000cU, 0x0011U,       // move-result-object v0; return-object v0
    };
    split_reflection_method.body.references = {
        {std::string("extra.Target"), 1U, false},
        {dex::MethodReference{
             "Ljava/lang/Class;", "forName", "Ljava/lang/Class;",
             {"Ljava/lang/String;"}},
         3U, false},
    };
    split_reflection_class.direct_methods.push_back(
        std::move(split_reflection_method));
    split_reflection_builder.AddClass(std::move(split_reflection_class));
    const auto split_reflection = guard::DexModelLowering(
        SplitReflectionConfig()).Apply(dex::DexFile::Parse(
            split_reflection_builder.Build()));
    assert(split_reflection.split_classes == 1U);
    assert(split_reflection.pass_applications.at(
               "reflection.indirect_targets") == 1U);
    const auto split_reflection_dex = dex::DexFile::Parse(
        split_reflection.bytes);
    dex::VerifyDexOrThrow(split_reflection_dex,
                          dex::VerificationLevel::Full);

    // Static utility classes are merged only when no type identity is exposed.
    dex::DexBuilder merge_builder(38U);
    dex::ClassSpec first;
    first.descriptor = "Lextra/First;";
    first.direct_methods.push_back(ConstantMethod("one"));
    dex::ClassSpec second;
    second.descriptor = "Lextra/Second;";
    second.direct_methods.push_back(ConstantMethod("two"));
    merge_builder.AddClass(std::move(first));
    merge_builder.AddClass(std::move(second));
    const auto merge_source = dex::DexFile::Parse(merge_builder.Build());
    auto merged = guard::DexModelLowering(Config("structure.class_merging")).Apply(
        merge_source);
    assert(merged.merged_classes == 1U);
    const auto merged_dex = dex::DexFile::Parse(merged.bytes);
    dex::VerifyDexOrThrow(merged_dex, dex::VerificationLevel::Full);
    assert(merged_dex.classes().size() == 1U);

    // A live interface contract is converted together with its implementor,
    // constructor chain, and invoke-interface callsites.
    dex::DexBuilder interface_builder(38U);
    dex::ClassSpec marker;
    marker.descriptor = "Lextra/Marker;";
    marker.access_flags = 0x0601U;
    dex::MethodSpec marker_value;
    marker_value.name = "value";
    marker_value.return_type = "I";
    marker_value.access_flags = 0x0401U;
    marker.virtual_methods.push_back(std::move(marker_value));
    interface_builder.AddClass(std::move(marker));
    dex::ClassSpec implementation;
    implementation.descriptor = "Lextra/Implementation;";
    implementation.interfaces.push_back("Lextra/Marker;");
    dex::MethodSpec implementation_constructor;
    implementation_constructor.name = "<init>";
    implementation_constructor.return_type = "V";
    implementation_constructor.access_flags = 0x0001U;
    implementation_constructor.body.registers_size = 1U;
    implementation_constructor.body.ins_size = 1U;
    implementation_constructor.body.outs_size = 1U;
    implementation_constructor.body.code_units = {
        0x1070U, 0U, 0x0000U, 0x000eU};
    implementation_constructor.body.references.push_back({
        dex::MethodReference{"Ljava/lang/Object;", "<init>", "V", {}},
        1U, false});
    implementation.direct_methods.push_back(
        std::move(implementation_constructor));
    auto implementation_value = ConstantMethod("value");
    implementation_value.access_flags = 0x0001U;
    implementation_value.body.registers_size = 2U;
    implementation_value.body.ins_size = 1U;
    implementation.virtual_methods.push_back(std::move(implementation_value));
    interface_builder.AddClass(std::move(implementation));
    dex::ClassSpec interface_user;
    interface_user.descriptor = "Lextra/InterfaceUser;";
    dex::MethodSpec invoke_contract;
    invoke_contract.name = "read";
    invoke_contract.return_type = "I";
    invoke_contract.parameter_types = {"Lextra/Marker;"};
    invoke_contract.access_flags = 0x0009U;
    invoke_contract.body.registers_size = 1U;
    invoke_contract.body.ins_size = 1U;
    invoke_contract.body.outs_size = 1U;
    invoke_contract.body.code_units = {
        0x1072U, 0U, 0x0000U, 0x000aU, 0x000fU};
    invoke_contract.body.references.push_back({
        dex::MethodReference{"Lextra/Marker;", "value", "I", {}},
        1U, false});
    interface_user.direct_methods.push_back(std::move(invoke_contract));
    interface_builder.AddClass(std::move(interface_user));
    const auto interface_source = dex::DexFile::Parse(interface_builder.Build());
    auto converted = guard::DexModelLowering(
        Config("structure.interface_abstract_conversion")).Apply(interface_source);
    assert(converted.converted_classes == 1U);
    const auto converted_dex = dex::DexFile::Parse(converted.bytes);
    dex::VerifyDexOrThrow(converted_dex, dex::VerificationLevel::Full);
    const auto class_index = [&](std::string_view descriptor) {
        for (std::size_t index = 0U; index < converted_dex.classes().size();
             ++index) {
            if (converted_dex.descriptor(
                    converted_dex.classes()[index].class_idx) == descriptor) {
                return index;
            }
        }
        return converted_dex.classes().size();
    };
    const auto marker_index = class_index("Lextra/Marker;");
    const auto implementation_index = class_index("Lextra/Implementation;");
    const auto user_index = class_index("Lextra/InterfaceUser;");
    assert(marker_index < converted_dex.classes().size());
    assert(implementation_index < converted_dex.classes().size());
    assert(user_index < converted_dex.classes().size());
    assert((converted_dex.classes()[marker_index].access_flags & 0x0200U) == 0U);
    assert((converted_dex.classes()[marker_index].access_flags & 0x0400U) != 0U);
    assert(converted_dex.descriptor(
        converted_dex.classes()[implementation_index].superclass_idx) ==
        "Lextra/Marker;");
    const auto user_code = dex::DecodeCodeItem(
        converted_dex,
        converted_dex.class_data(user_index).direct_methods.front().code_off);
    assert(user_code.instructions.front().opcode == 0x6eU);

    // The reverse direction removes a trivial abstract base constructor,
    // moves subclasses to Object + implements, and changes virtual dispatch
    // to invoke-interface.
    dex::DexBuilder abstract_builder(38U);
    dex::ClassSpec abstract_base;
    abstract_base.descriptor = "Lextra/AbstractBase;";
    abstract_base.access_flags = 0x0401U;
    dex::MethodSpec base_constructor;
    base_constructor.name = "<init>";
    base_constructor.return_type = "V";
    base_constructor.access_flags = 0x0001U;
    base_constructor.body.registers_size = 1U;
    base_constructor.body.ins_size = 1U;
    base_constructor.body.outs_size = 1U;
    base_constructor.body.code_units = {
        0x1070U, 0U, 0x0000U, 0x000eU};
    base_constructor.body.references.push_back({
        dex::MethodReference{"Ljava/lang/Object;", "<init>", "V", {}},
        1U, false});
    abstract_base.direct_methods.push_back(std::move(base_constructor));
    dex::MethodSpec abstract_value;
    abstract_value.name = "value";
    abstract_value.return_type = "I";
    abstract_value.access_flags = 0x0401U;
    abstract_base.virtual_methods.push_back(std::move(abstract_value));
    abstract_builder.AddClass(std::move(abstract_base));
    dex::ClassSpec subclass;
    subclass.descriptor = "Lextra/Subclass;";
    subclass.superclass = "Lextra/AbstractBase;";
    dex::MethodSpec subclass_constructor;
    subclass_constructor.name = "<init>";
    subclass_constructor.return_type = "V";
    subclass_constructor.access_flags = 0x0001U;
    subclass_constructor.body.registers_size = 1U;
    subclass_constructor.body.ins_size = 1U;
    subclass_constructor.body.outs_size = 1U;
    subclass_constructor.body.code_units = {
        0x1070U, 0U, 0x0000U, 0x000eU};
    subclass_constructor.body.references.push_back({
        dex::MethodReference{"Lextra/AbstractBase;", "<init>", "V", {}},
        1U, false});
    subclass.direct_methods.push_back(std::move(subclass_constructor));
    auto subclass_value = ConstantMethod("value");
    subclass_value.access_flags = 0x0001U;
    subclass_value.body.registers_size = 2U;
    subclass_value.body.ins_size = 1U;
    subclass.virtual_methods.push_back(std::move(subclass_value));
    abstract_builder.AddClass(std::move(subclass));
    dex::ClassSpec abstract_user;
    abstract_user.descriptor = "Lextra/AbstractUser;";
    dex::MethodSpec invoke_abstract;
    invoke_abstract.name = "read";
    invoke_abstract.return_type = "I";
    invoke_abstract.parameter_types = {"Lextra/AbstractBase;"};
    invoke_abstract.access_flags = 0x0009U;
    invoke_abstract.body.registers_size = 1U;
    invoke_abstract.body.ins_size = 1U;
    invoke_abstract.body.outs_size = 1U;
    invoke_abstract.body.code_units = {
        0x106eU, 0U, 0x0000U, 0x000aU, 0x000fU};
    invoke_abstract.body.references.push_back({
        dex::MethodReference{"Lextra/AbstractBase;", "value", "I", {}},
        1U, false});
    abstract_user.direct_methods.push_back(std::move(invoke_abstract));
    abstract_builder.AddClass(std::move(abstract_user));
    const auto abstract_source = dex::DexFile::Parse(abstract_builder.Build());
    const auto interface_converted = guard::DexModelLowering(
        Config("structure.interface_abstract_conversion")).Apply(
            abstract_source);
    assert(interface_converted.converted_classes == 1U);
    const auto interface_dex = dex::DexFile::Parse(
        interface_converted.bytes);
    dex::VerifyDexOrThrow(interface_dex, dex::VerificationLevel::Full);
    std::size_t base_index = interface_dex.classes().size();
    std::size_t subclass_index = interface_dex.classes().size();
    std::size_t abstract_user_index = interface_dex.classes().size();
    for (std::size_t index = 0U; index < interface_dex.classes().size();
         ++index) {
        const auto descriptor = interface_dex.descriptor(
            interface_dex.classes()[index].class_idx);
        if (descriptor == "Lextra/AbstractBase;") base_index = index;
        if (descriptor == "Lextra/Subclass;") subclass_index = index;
        if (descriptor == "Lextra/AbstractUser;") abstract_user_index = index;
    }
    assert(base_index < interface_dex.classes().size());
    assert(subclass_index < interface_dex.classes().size());
    assert(abstract_user_index < interface_dex.classes().size());
    assert((interface_dex.classes()[base_index].access_flags & 0x0200U) != 0U);
    assert(interface_dex.descriptor(
        interface_dex.classes()[subclass_index].superclass_idx) ==
        "Ljava/lang/Object;");
    const auto subclass_interfaces = interface_dex.type_list(
        interface_dex.classes()[subclass_index].interfaces_off);
    assert(std::any_of(subclass_interfaces.begin(), subclass_interfaces.end(),
                       [&](const auto type) {
                           return interface_dex.descriptor(type) ==
                               "Lextra/AbstractBase;";
                       }));
    const auto abstract_user_code = dex::DecodeCodeItem(
        interface_dex,
        interface_dex.class_data(abstract_user_index)
            .direct_methods.front().code_off);
    assert(abstract_user_code.instructions.front().opcode == 0x72U);

    // Array access is redirected through a generated static accessor while
    // preserving the legal static field initialization contract.
    dex::DexBuilder array_builder(38U);
    dex::ClassSpec array_class;
    array_class.descriptor = "Lextra/Arrays;";
    dex::FieldSpec values;
    values.name = "values";
    values.type = "[I";
    values.access_flags = 0x0009U;
    array_class.static_fields.push_back(std::move(values));
    auto get = ConstantMethod("get", "I");
    get.parameter_types = {"I"};
    get.body.registers_size = 2U;
    get.body.ins_size = 1U;
    get.body.code_units = {
        0x0062U, 0U,
        0x0044U, 0x0100U,
        0x000fU,
    };
    get.body.references.push_back({dex::FieldReference{
        "Lextra/Arrays;", "values", "[I"}, 1U, false});
    array_class.direct_methods.push_back(std::move(get));
    array_builder.AddClass(std::move(array_class));
    const auto array_source = dex::DexFile::Parse(array_builder.Build());
    auto arrays = guard::DexModelLowering(Config("data.array_virtualization")).Apply(
        array_source);
    assert(arrays.virtualized_arrays == 1U);
    const auto arrays_dex = dex::DexFile::Parse(arrays.bytes);
    dex::VerifyDexOrThrow(arrays_dex, dex::VerificationLevel::Full);
    const auto& array_data = arrays_dex.class_data(0U);
    const auto get_method = std::find_if(
        array_data.direct_methods.begin(), array_data.direct_methods.end(),
        [&](const auto& encoded) {
            return arrays_dex.string(
                arrays_dex.methods().at(encoded.method_idx).name_idx) == "get";
        });
    assert(get_method != array_data.direct_methods.end());
    const auto get_code = dex::DecodeCodeItem(arrays_dex, get_method->code_off);
    assert(std::none_of(get_code.instructions.begin(), get_code.instructions.end(),
                        [](const auto& instruction) {
                            return instruction.opcode == 0x62U ||
                                   instruction.opcode == 0x44U ||
                                   (instruction.opcode == 0x00U &&
                                    instruction.code_units.front() == 0U);
                        }));
    assert(std::any_of(get_code.instructions.begin(), get_code.instructions.end(),
                       [](const auto& instruction) {
                           return instruction.opcode == 0x71U;
                       }));

    // Storage splitting materializes two backing arrays after <clinit> and
    // rewrites proven read-only element loads through a boundary dispatcher.
    dex::DexBuilder split_array_builder(38U);
    dex::ClassSpec split_array_class;
    split_array_class.descriptor = "Lextra/SplitArrays;";
    dex::FieldSpec split_values;
    split_values.name = "values";
    split_values.type = "[I";
    split_values.access_flags = 0x001aU; // private static final
    split_array_class.static_fields.push_back(std::move(split_values));
    dex::MethodSpec clinit;
    clinit.name = "<clinit>";
    clinit.return_type = "V";
    clinit.access_flags = 0x0008U;
    clinit.body.registers_size = 1U;
    clinit.body.code_units = {
        0x4012U,             // const/4 v0, 4
        0x0023U, 0U,        // new-array v0, v0, int[]
        0x0069U, 0U,        // sput-object v0, values
        0x000eU,
    };
    clinit.body.references = {
        {dex::TypeReference{"[I"}, 2U, false},
        {dex::FieldReference{"Lextra/SplitArrays;", "values", "[I"},
         4U, false},
    };
    split_array_class.direct_methods.push_back(std::move(clinit));
    dex::MethodSpec element;
    element.name = "element";
    element.return_type = "I";
    element.parameter_types = {"I"};
    element.access_flags = 0x0009U;
    element.body.registers_size = 2U;
    element.body.ins_size = 1U;
    element.body.code_units = {
        0x0062U, 0U, // sget-object v0, values
        0x0044U, 0x0100U, // aget v0, v0, p0
        0x000fU,
    };
    element.body.references.push_back({dex::FieldReference{
        "Lextra/SplitArrays;", "values", "[I"}, 1U, false});
    split_array_class.direct_methods.push_back(std::move(element));
    split_array_builder.AddClass(std::move(split_array_class));
    const auto split_array_source = dex::DexFile::Parse(
        split_array_builder.Build());
    const auto split_arrays = guard::DexModelLowering(
        Config("data.array_splitting")).Apply(split_array_source);
    assert(split_arrays.split_arrays == 1U);
    assert(split_arrays.pass_applications.at("data.array_splitting") == 1U);
    const auto split_array_dex = dex::DexFile::Parse(split_arrays.bytes);
    dex::VerifyDexOrThrow(split_array_dex,
                         dex::VerificationLevel::Full);
    const auto& split_array_data = split_array_dex.class_data(0U);
    assert(split_array_data.static_fields.size() == 3U);
    const auto find_direct = [&](std::string_view name) {
        return std::find_if(
            split_array_data.direct_methods.begin(),
            split_array_data.direct_methods.end(),
            [&](const auto& encoded) {
                return split_array_dex.string(
                    split_array_dex.methods().at(encoded.method_idx).name_idx) == name;
            });
    };
    const auto rewritten_element = find_direct("element");
    assert(rewritten_element != split_array_data.direct_methods.end());
    const auto rewritten_element_code = dex::DecodeCodeItem(
        split_array_dex, rewritten_element->code_off);
    assert(std::none_of(rewritten_element_code.instructions.begin(),
                        rewritten_element_code.instructions.end(),
                        [](const auto& instruction) {
                            return instruction.opcode == 0x62U ||
                                   instruction.opcode == 0x44U;
                        }));
    assert(std::any_of(rewritten_element_code.instructions.begin(),
                       rewritten_element_code.instructions.end(),
                       [](const auto& instruction) {
                           return instruction.opcode == 0x71U;
                       }));
    bool found_split_initializer = false;
    bool found_split_dispatch = false;
    for (const auto& encoded : split_array_data.direct_methods) {
        const auto code = dex::DecodeCodeItem(split_array_dex,
                                              encoded.code_off);
        const auto invokes = std::count_if(
            code.instructions.begin(), code.instructions.end(),
            [](const auto& instruction) { return instruction.opcode == 0x71U; });
        const auto new_arrays = std::count_if(
            code.instructions.begin(), code.instructions.end(),
            [](const auto& instruction) { return instruction.opcode == 0x23U; });
        const auto array_gets = std::count_if(
            code.instructions.begin(), code.instructions.end(),
            [](const auto& instruction) { return instruction.opcode == 0x44U; });
        found_split_initializer = found_split_initializer ||
            (invokes == 2 && new_arrays == 2);
        found_split_dispatch = found_split_dispatch ||
            (invokes >= 1 && array_gets == 2 &&
             std::any_of(code.instructions.begin(), code.instructions.end(),
                         [](const auto& instruction) {
                             return instruction.opcode == 0x35U ||
                                    instruction.opcode == 0x39U;
                         }));
    }
    assert(found_split_initializer && found_split_dispatch);

    // Enum lowering rewrites a proven ordinal equality chain to a per-enum
    // encoded integer protocol and changes the compared constant in lockstep.
    dex::DexBuilder enum_builder(38U);
    dex::ClassSpec enum_class;
    enum_class.descriptor = "Lextra/Kind;";
    enum_class.access_flags = 0x4011U;
    dex::FieldSpec enum_value;
    enum_value.name = "VALUE";
    enum_value.type = "Lextra/Kind;";
    enum_value.access_flags = 0x4019U;
    enum_class.static_fields.push_back(std::move(enum_value));
    enum_builder.AddClass(std::move(enum_class));
    dex::ClassSpec enum_user;
    enum_user.descriptor = "Lextra/EnumUser;";
    dex::MethodSpec enum_compare;
    enum_compare.name = "isFirst";
    enum_compare.return_type = "I";
    enum_compare.access_flags = 0x0009U;
    enum_compare.body.registers_size = 2U;
    enum_compare.body.outs_size = 1U;
    enum_compare.body.code_units = {
        0x0062U, 0U,             // sget-object v0, Kind.VALUE
        0x106eU, 0U, 0x0000U,   // invoke-virtual {v0}, Kind.ordinal
        0x000aU,                 // move-result v0
        0x0112U,                 // const/4 v1, 0
        0x1033U, 0x0003U,        // if-ne v0, v1, return
        0x0012U,                 // const/4 v0, 0
        0x000fU,
    };
    enum_compare.body.references = {
        {dex::FieldReference{
             "Lextra/Kind;", "VALUE", "Lextra/Kind;"}, 1U, false},
        {dex::MethodReference{
             "Lextra/Kind;", "ordinal", "I", {}}, 3U, false},
    };
    enum_user.direct_methods.push_back(std::move(enum_compare));
    enum_builder.AddClass(std::move(enum_user));
    const auto enum_source = dex::DexFile::Parse(enum_builder.Build());
    auto lowered_enum = guard::DexModelLowering(Config("data.enum_lowering")).Apply(
        enum_source);
    assert(lowered_enum.lowered_enums == 1U);
    assert(lowered_enum.pass_applications.at("data.enum_lowering") == 1U);
    const auto enum_dex = dex::DexFile::Parse(lowered_enum.bytes);
    dex::VerifyDexOrThrow(enum_dex, dex::VerificationLevel::Full);
    bool found_enum_codec = false;
    bool found_encoded_callsite = false;
    for (std::size_t class_index = 0U;
         class_index < enum_dex.classes().size(); ++class_index) {
        const auto descriptor = enum_dex.descriptor(
            enum_dex.classes()[class_index].class_idx);
        const auto& data = enum_dex.class_data(class_index);
        for (const auto& encoded : data.virtual_methods) {
            const auto code = dex::DecodeCodeItem(enum_dex, encoded.code_off);
            found_enum_codec = found_enum_codec ||
                (descriptor == "Lextra/Kind;" &&
                 std::any_of(code.instructions.begin(), code.instructions.end(),
                             [](const auto& instruction) {
                                 return instruction.opcode == 0x23U;
                             }) &&
                 std::any_of(code.instructions.begin(), code.instructions.end(),
                             [](const auto& instruction) {
                                 return instruction.opcode == 0x4bU;
                             }) &&
                 std::any_of(code.instructions.begin(), code.instructions.end(),
                             [](const auto& instruction) {
                                 return instruction.opcode == 0x44U;
                             }));
        }
        for (const auto& encoded : data.direct_methods) {
            const auto& id = enum_dex.methods().at(encoded.method_idx);
            if (descriptor != "Lextra/EnumUser;" ||
                enum_dex.string(id.name_idx) != "isFirst") {
                continue;
            }
            const auto code = dex::DecodeCodeItem(enum_dex, encoded.code_off);
            const auto invoke = std::find_if(
                code.instructions.begin(), code.instructions.end(),
                [](const auto& instruction) {
                    return instruction.opcode == 0x6eU;
                });
            assert(invoke != code.instructions.end());
            const auto& target = enum_dex.methods().at(
                invoke->code_units[1U]);
            found_encoded_callsite =
                enum_dex.string(target.name_idx) != "ordinal" &&
                std::any_of(code.instructions.begin(), code.instructions.end(),
                            [](const auto& instruction) {
                                return instruction.opcode == 0x14U;
                            });
        }
    }
    assert(found_enum_codec && found_encoded_callsite);

    // Loading-path encryption uses the same verifier-safe string runtime even
    // when the general string pass is disabled.
    dex::DexBuilder path_builder(38U);
    dex::ClassSpec path_class;
    path_class.descriptor = "Lextra/Loader;";
    dex::MethodSpec path_method;
    path_method.name = "path";
    path_method.return_type = "Ldalvik/system/DexClassLoader;";
    path_method.access_flags = 0x0009U;
    path_method.body.registers_size = 5U;
    path_method.body.outs_size = 5U;
    path_method.body.code_units = {
        0x0022U, 0U,       // new-instance v0, DexClassLoader
        0x011aU, 0U,       // const-string v1, dexPath
        0x021aU, 0U,       // const-string v2, optimizedDirectory
        0x0312U,           // const/4 v3, #0 (library path)
        0x0412U,           // const/4 v4, #0 (parent)
        0x5470U, 0U, 0x3210U, // invoke-direct {v0..v4}, <init>
        0x0011U,
    };
    path_method.body.references = {
        {dex::TypeReference{"Ldalvik/system/DexClassLoader;"}, 1U, false},
        {std::string("/data/app/secret.dex"), 3U, false},
        {std::string("/data/app/oat"), 5U, false},
        {dex::MethodReference{
             "Ldalvik/system/DexClassLoader;", "<init>", "V",
             {"Ljava/lang/String;", "Ljava/lang/String;",
              "Ljava/lang/String;", "Ljava/lang/ClassLoader;"}},
         9U, false},
    };
    path_class.direct_methods.push_back(std::move(path_method));
    path_builder.AddClass(std::move(path_class));
    const auto path_source = dex::DexFile::Parse(path_builder.Build());
    auto encrypted_path = guard::DexModelLowering(Config("loading.encrypted_paths")).Apply(
        path_source);
    assert(encrypted_path.encrypted_strings == 1U);
    const auto path_dex = dex::DexFile::Parse(encrypted_path.bytes);
    dex::VerifyDexOrThrow(path_dex, dex::VerificationLevel::Full);
    for (const auto& value : path_dex.strings()) assert(value.mutf8 != "/data/app/secret.dex");
    return 0;
}
