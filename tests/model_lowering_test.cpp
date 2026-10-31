#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"
#include "birch/guard/model_lowering.h"
#include "birch/guard/string_runtime.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <fstream>
#include <string>

int main() {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lmodel/Business;";
    birch::dex::MethodSpec method;
    method.name = "work";
    method.return_type = "I";
    method.parameter_types = {"I"};
    method.access_flags = 0x0001U;
    method.body.registers_size = 2U;
    method.body.ins_size = 2U;
    method.body.code_units = {
        0x013dU, 6U,      // if-lez p1, return
        0x01d8U, 0xff01U, // add-int/lit8 p1, p1, -1
        0x0029U, 0xfffcU, // goto/16 loop header
        0x010fU,          // return p1
    };
    klass.virtual_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto source = birch::dex::DexFile::Parse(builder.Build());

    const auto config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 551122,
      "scope": {"protect": [{"pattern": "Lmodel/**;"}], "keep": []},
      "passes": {
        "cfg.tail_recursion": {"enabled": true, "intensity": 1.0,
                                "max_applications_per_method": 1}
      }
    })json");
    const auto lowered = birch::guard::DexModelLowering(config).Apply(source);
    assert(lowered.tail_recursive_methods == 1U);
    assert(lowered.outlined_methods == 0U);
    const auto output = birch::dex::DexFile::Parse(lowered.bytes);
    birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
    const auto& data = output.class_data(0U);
    assert(data.virtual_methods.size() == 1U);
    assert(data.direct_methods.size() == 1U);
    const auto wrapper = birch::dex::DecodeCodeItem(
        output, data.virtual_methods.front().code_off);
    assert(wrapper.instructions.front().opcode == 0x12U);
    assert(wrapper.instructions.at(1U).opcode == 0x70U);
    assert(wrapper.instructions.back().opcode == 0x0fU);

    bool found_tail_helper = false;
    for (const auto& encoded : data.direct_methods) {
        const auto& id = output.methods().at(encoded.method_idx);
        const auto parameters = output.type_list(
            output.protos().at(id.proto_idx).parameters_off);
        const auto code = birch::dex::DecodeCodeItem(output, encoded.code_off);
        if (parameters.size() == 2U) {
            found_tail_helper = true;
            assert(code.instructions.front().opcode == 0x3dU);
            assert(std::count_if(code.instructions.begin(), code.instructions.end(),
                                 [](const auto& instruction) {
                                     return instruction.opcode == 0x70U;
                                 }) == 1);
            assert(std::count_if(code.instructions.begin(), code.instructions.end(),
                                 [](const auto& instruction) {
                                     return instruction.opcode == 0x3dU;
                                 }) == 2);
            assert(std::none_of(code.instructions.begin(), code.instructions.end(),
                                [](const auto& instruction) {
                                    return instruction.opcode == 0x29U;
                                }));
        }
    }
    assert(found_tail_helper);

    birch::dex::DexBuilder split_builder(38U);
    birch::dex::ClassSpec split_class;
    split_class.descriptor = "Lmodel/Split;";
    birch::dex::MethodSpec split_method;
    split_method.name = "compute";
    split_method.return_type = "I";
    split_method.parameter_types = {"I"};
    split_method.access_flags = 0x0001U;
    split_method.body.registers_size = 2U;
    split_method.body.ins_size = 2U;
    split_method.body.code_units = {
        0x01d8U, 0x0101U, // add-int/lit8 p1, p1, 1
        0x010fU,          // return p1
    };
    split_class.virtual_methods.push_back(std::move(split_method));
    split_builder.AddClass(std::move(split_class));
    const auto split_source = birch::dex::DexFile::Parse(split_builder.Build());
    const auto split_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 551122,
      "scope": {"protect": [{"pattern": "Lmodel/Split;"}], "keep": []},
      "passes": {
        "structure.method_splitting": {"enabled": true, "intensity": 1.0,
                                        "max_applications_per_method": 1}
      }
    })json");
    const auto split = birch::guard::DexModelLowering(split_config).Apply(
        split_source);
    assert(split.split_methods == 1U);
    assert(split.tail_recursive_methods == 0U);
    const auto split_dex = birch::dex::DexFile::Parse(split.bytes);
    birch::dex::VerifyDexOrThrow(split_dex,
                                 birch::dex::VerificationLevel::Full);
    assert(split_dex.class_data(0U).virtual_methods.size() == 1U);
    assert(split_dex.class_data(0U).direct_methods.size() == 8U);
    const auto split_entry = birch::dex::DecodeCodeItem(
        split_dex, split_dex.class_data(0U).virtual_methods.front().code_off);
    assert(split_entry.instructions.front().opcode == 0x12U);
    assert(split_entry.instructions.at(1U).opcode == 0x70U);
    assert(split_entry.instructions.at(2U).opcode == 0x0aU);
    assert(split_entry.instructions.back().opcode == 0x0fU);
    std::size_t split_state_hops = 0U;
    bool found_split_body = false;
    for (const auto& encoded : split_dex.class_data(0U).direct_methods) {
        const auto fragment = birch::dex::DecodeCodeItem(
            split_dex, encoded.code_off);
        assert(std::none_of(
            fragment.instructions.begin(), fragment.instructions.end(),
            [](const auto& instruction) {
                return instruction.kind != birch::dex::InstructionKind::Payload &&
                       instruction.opcode == 0x00U;
            }));
        if (fragment.instructions.front().opcode == 0xd8U) {
            found_split_body = true;
            continue;
        }
        const auto has_state_mix = fragment.instructions.size() >= 4U &&
            fragment.instructions[0U].opcode == 0xdfU &&
            fragment.instructions[1U].opcode == 0xd8U &&
            fragment.instructions[2U].opcode == 0x70U;
        if (has_state_mix) ++split_state_hops;
    }
    assert(found_split_body && split_state_hops == 7U);

    const auto proxy_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 551122,
      "scope": {"protect": [{"pattern": "Lmodel/**;"}], "keep": []},
      "passes": {
        "structure.proxy_stubs": {"enabled": true, "intensity": 1.0,
                                    "max_applications_per_method": 1}
      }
    })json");
    const auto proxied = birch::guard::DexModelLowering(proxy_config).Apply(source);
    assert(proxied.proxy_methods == 1U);
    const auto proxy_dex = birch::dex::DexFile::Parse(proxied.bytes);
    birch::dex::VerifyDexOrThrow(proxy_dex,
                                 birch::dex::VerificationLevel::Full);
    assert(proxy_dex.classes().size() == 2U);
    std::size_t proxy_original_index = 0U;
    std::size_t proxy_hop_index = 0U;
    for (std::size_t i = 0U; i < proxy_dex.classes().size(); ++i) {
        const auto descriptor = proxy_dex.descriptor(
            proxy_dex.classes()[i].class_idx);
        if (descriptor == "Lmodel/Business;") {
            proxy_original_index = i;
        } else {
            proxy_hop_index = i;
            assert(descriptor.starts_with("La"));
            assert(descriptor.find("model") == std::string::npos);
        }
    }
    const auto proxy_entry = birch::dex::DecodeCodeItem(
        proxy_dex,
        proxy_dex.class_data(proxy_original_index).virtual_methods.front().code_off);
    assert(proxy_entry.instructions.front().opcode == 0x71U);
    const auto proxy_hop = birch::dex::DecodeCodeItem(
        proxy_dex,
        proxy_dex.class_data(proxy_hop_index).direct_methods.front().code_off);
    assert(proxy_hop.instructions.front().opcode == 0x71U);

    birch::dex::DexBuilder inline_builder(38U);
    birch::dex::ClassSpec inline_class;
    inline_class.descriptor = "Lmodel/Inline;";
    birch::dex::MethodSpec constant;
    constant.name = "constant";
    constant.return_type = "I";
    constant.access_flags = 0x000aU; // private static
    constant.body.registers_size = 1U;
    constant.body.code_units = {0x7012U, 0x000fU};
    inline_class.direct_methods.push_back(std::move(constant));
    birch::dex::MethodSpec caller;
    caller.name = "caller";
    caller.return_type = "I";
    caller.body.registers_size = 1U;
    caller.body.code_units = {0x0071U, 0U, 0U, 0x000aU, 0x000fU};
    caller.body.references.push_back({
        birch::dex::MethodReference{"Lmodel/Inline;", "constant", "I", {}},
        1U, false});
    inline_class.direct_methods.push_back(std::move(caller));
    inline_builder.AddClass(std::move(inline_class));
    const auto inline_source = birch::dex::DexFile::Parse(inline_builder.Build());
    const auto inline_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 2211,
      "scope": {"protect": [{"pattern": "Lmodel/Inline;"}], "keep": []},
      "passes": {
        "structure.method_inlining": {"enabled": true, "intensity": 1.0}
      }
    })json");
    const auto inlined = birch::guard::DexModelLowering(inline_config).Apply(
        inline_source);
    assert(inlined.inlined_calls == 1U);
    const auto inline_output = birch::dex::DexFile::Parse(inlined.bytes);
    birch::dex::VerifyDexOrThrow(inline_output,
                                 birch::dex::VerificationLevel::Full);
    const auto& inline_data = inline_output.class_data(0U);
    const auto caller_method = std::find_if(
        inline_data.direct_methods.begin(), inline_data.direct_methods.end(),
        [&](const auto& encoded) {
            return inline_output.string(
                inline_output.methods().at(encoded.method_idx).name_idx) == "caller";
        });
    assert(caller_method != inline_data.direct_methods.end());
    const auto caller_code = birch::dex::DecodeCodeItem(
        inline_output, caller_method->code_off);
    assert(caller_code.instructions.front().opcode == 0x12U);
    assert(std::none_of(caller_code.instructions.begin(), caller_code.instructions.end(),
                        [](const auto& instruction) {
                            return instruction.opcode == 0x71U;
                        }));

    birch::dex::DexBuilder class_split_builder(38U);
    birch::dex::ClassSpec class_split_class;
    class_split_class.descriptor = "Lmodel/ClassSplit;";
    birch::dex::MethodSpec class_split_method;
    class_split_method.name = "pure";
    class_split_method.return_type = "I";
    class_split_method.access_flags = 0x000aU; // private static
    class_split_method.body.registers_size = 1U;
    class_split_method.body.code_units = {0x7012U, 0x000fU};
    class_split_class.direct_methods.push_back(std::move(class_split_method));
    class_split_builder.AddClass(std::move(class_split_class));
    const auto class_split_source = birch::dex::DexFile::Parse(
        class_split_builder.Build());
    const auto class_split_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 7744,
      "scope": {"protect": [{"pattern": "Lmodel/ClassSplit;"}], "keep": []},
      "passes": {
        "structure.class_splitting": {"enabled": true, "intensity": 1.0,
                                       "max_applications_per_method": 1}
      }
    })json");
    const auto class_split = birch::guard::DexModelLowering(class_split_config).Apply(
        class_split_source);
    assert(class_split.split_classes == 1U);
    const auto class_split_output = birch::dex::DexFile::Parse(class_split.bytes);
    birch::dex::VerifyDexOrThrow(class_split_output,
                                 birch::dex::VerificationLevel::Full);
    assert(class_split_output.classes().size() == 2U);
    std::size_t original_split_index = 0U;
    for (std::size_t i = 0U; i < class_split_output.classes().size(); ++i) {
        if (class_split_output.descriptor(
                class_split_output.classes()[i].class_idx) ==
            "Lmodel/ClassSplit;") {
            original_split_index = i;
            break;
        }
    }
    const auto& split_data = class_split_output.class_data(original_split_index);
    const auto wrapper_method = split_data.direct_methods.front();
    const auto wrapper_code = birch::dex::DecodeCodeItem(
        class_split_output, wrapper_method.code_off);
    assert(wrapper_code.instructions.front().opcode == 0x71U);
    const auto target_method_index = wrapper_code.instructions.front().code_units.at(1U);
    const auto target_owner = class_split_output.descriptor(
        class_split_output.methods().at(target_method_index).class_idx);
    assert(target_owner != "Lmodel/ClassSplit;");
    assert(target_owner.starts_with("La"));
    assert(target_owner.find("ClassSplit") == std::string::npos);

    birch::dex::DexBuilder metadata_builder(38U);
    birch::dex::ClassSpec metadata_class;
    metadata_class.descriptor = "Lmodel/Metadata;";
    birch::dex::MethodSpec metadata_method;
    metadata_method.name = "work";
    metadata_method.body.registers_size = 1U;
    metadata_method.body.code_units = {0x000eU};
    birch::dex::DebugInfoSpec metadata_debug;
    metadata_debug.line_start = 1U;
    metadata_method.body.debug_info = std::move(metadata_debug);
    metadata_class.direct_methods.push_back(std::move(metadata_method));
    metadata_builder.AddClass(std::move(metadata_class));
    const auto metadata_source = birch::dex::DexFile::Parse(metadata_builder.Build());
    const auto metadata_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 3322,
      "scope": {"protect": [{"pattern": "Lmodel/Metadata;"}], "keep": []},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "anti_analysis.annotation_noise": {"enabled": true, "intensity": 1.0,
                                             "max_applications_per_method": 1},
        "anti_analysis.annotation_forgery": {"enabled": true, "intensity": 1.0,
                                               "max_applications_per_method": 1},
        "anti_analysis.debug_local_noise": {"enabled": true, "intensity": 1.0,
                                              "max_applications_per_method": 1}
      }
    })json");
    const auto metadata = birch::guard::DexModelLowering(metadata_config).Apply(
        metadata_source);
    assert(metadata.annotation_noise_items == 16U);
    assert(metadata.debug_noise_methods == 1U);
    const auto metadata_output = birch::dex::DexFile::Parse(metadata.bytes);
    birch::dex::VerifyDexOrThrow(metadata_output,
                                 birch::dex::VerificationLevel::Full);
    assert(metadata_output.classes().front().annotations_off != 0U);
    const auto metadata_code = birch::dex::DecodeCodeItem(
        metadata_output,
        metadata_output.class_data(0U).direct_methods.front().code_off);
    assert(metadata_code.debug_info_off != 0U);

    birch::dex::DexBuilder string_builder(38U);
    birch::dex::ClassSpec string_class;
    string_class.descriptor = "Lmodel/StringData;";
    birch::dex::MethodSpec string_method;
    string_method.name = "secret";
    string_method.return_type = "Ljava/lang/String;";
    string_method.access_flags = 0x0009U;
    string_method.body.registers_size = 1U;
    string_method.body.code_units = {0x001aU, 0U, 0x0011U};
    string_method.body.references.push_back({std::string("Birch-secret-value-123456789"), 1U, false});
    string_class.direct_methods.push_back(std::move(string_method));
    string_builder.AddClass(std::move(string_class));
    const auto string_source = birch::dex::DexFile::Parse(string_builder.Build());
    const auto string_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 998877,
      "scope": {"protect": [{"pattern": "Lmodel/StringData;"}], "keep": []},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false},
        "data.string_encryption": {"enabled": true, "intensity": 1.0,
                                      "max_applications_per_method": 8},
        "data.string_splitting": {"enabled": true, "intensity": 1.0,
                                    "max_applications_per_method": 8}
      }
    })json");
    const auto string_lowered = birch::guard::DexModelLowering(string_config).Apply(
        string_source);
    assert(string_lowered.encrypted_strings == 1U);
    const auto string_output = birch::dex::DexFile::Parse(string_lowered.bytes);
    birch::dex::VerifyDexOrThrow(string_output, birch::dex::VerificationLevel::Full);
    assert(std::none_of(string_output.strings().begin(), string_output.strings().end(),
                        [&](const auto& value) {
                            return value.mutf8 == "Birch-secret-value-123456789";
                        }));
    const auto string_class_index = static_cast<std::size_t>(std::distance(
        string_output.classes().begin(),
        std::find_if(string_output.classes().begin(), string_output.classes().end(),
                     [&](const auto& definition) {
                         return string_output.descriptor(definition.class_idx) ==
                                "Lmodel/StringData;";
                     })));
    assert(string_class_index < string_output.classes().size());
    const auto& string_data = string_output.class_data(string_class_index);
    const auto string_code = birch::dex::DecodeCodeItem(
        string_output, string_data.direct_methods.front().code_off);
    assert(string_code.instructions.front().opcode == 0x71U);
    assert(string_code.instructions.at(1U).opcode == 0x0cU);
    const auto combined_helper_name = birch::guard::RuntimeStringMethodName(
        "Birch-secret-value-123456789", 998877U);
    bool found_string_entry = false;
    std::size_t string_helper_classes = 0U;
    std::size_t string_helper_payload_methods = 0U;
    for (std::size_t class_index = 0U; class_index < string_output.classes().size(); ++class_index) {
        const auto descriptor = string_output.descriptor(
            string_output.classes()[class_index].class_idx);
        const auto& helper_data = string_output.class_data(class_index);
        const auto entry_class = std::any_of(
            helper_data.direct_methods.begin(), helper_data.direct_methods.end(),
            [&](const auto& encoded) {
                const auto& method_id = string_output.methods().at(encoded.method_idx);
                return string_output.string(method_id.name_idx) == combined_helper_name;
        });
        if (descriptor != "Lmodel/StringData;") {
            ++string_helper_classes;
            assert(!descriptor.starts_with("Lbirch/guard/Strings$"));
            assert(descriptor.find("birch/guard") == std::string::npos);
            found_string_entry = found_string_entry || entry_class;
            for (const auto& encoded : helper_data.direct_methods) {
                const auto code = birch::dex::DecodeCodeItem(
                    string_output, encoded.code_off);
                const auto has_payload = std::any_of(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.opcode == 0x26U;
                    });
                const auto has_byte_payload = std::any_of(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return !instruction.code_units.empty() &&
                               instruction.code_units.front() == 0x0300U &&
                               instruction.code_units.size() >= 2U &&
                               instruction.code_units[1U] == 1U;
                    });
                const auto has_byte_wipe = std::any_of(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.opcode == 0x4fU;
                    });
                const auto has_char_wipe = std::any_of(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.opcode == 0x50U;
                    });
                const auto has_string_literal = std::any_of(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.opcode == 0x1aU ||
                               instruction.opcode == 0x1bU;
                    });
                if (has_payload) ++string_helper_payload_methods;
                if (has_payload) {
                    assert(has_byte_payload && has_byte_wipe && has_char_wipe);
                }
                assert(!has_string_literal);
            }
        }
    }
    assert(found_string_entry);
    assert(string_helper_payload_methods >= 4U);
    assert(string_helper_payload_methods <= 8U);
    assert(string_helper_classes == string_helper_payload_methods + 1U);
    if (const auto* path = std::getenv("BIRCH_STRING_LOWERING_OUTPUT")) {
        std::ofstream stream(path, std::ios::binary);
        stream.write(reinterpret_cast<const char*>(string_lowered.bytes.data()),
                     static_cast<std::streamsize>(string_lowered.bytes.size()));
    }

    birch::dex::DexBuilder reflection_builder(38U);
    birch::dex::ClassSpec reflection_target;
    reflection_target.descriptor = "Lmodel/Target;";
    reflection_builder.AddClass(std::move(reflection_target));
    birch::dex::ClassSpec reflection_caller;
    reflection_caller.descriptor = "Lmodel/Reflector;";
    birch::dex::MethodSpec reflection_method;
    reflection_method.name = "load";
    reflection_method.return_type = "Ljava/lang/Class;";
    reflection_method.access_flags = 0x0009U;
    reflection_method.body.registers_size = 1U;
    reflection_method.body.outs_size = 1U;
    reflection_method.body.code_units = {
        0x001aU, 0U,             // const-string v0, "model.Target"
        0x1071U, 0U, 0x0000U,   // invoke-static {v0}, Class.forName
        0x000cU, 0x0011U,       // move-result-object v0; return-object v0
    };
    reflection_method.body.references = {
        {std::string("model.Target"), 1U, false},
        {birch::dex::MethodReference{
             "Ljava/lang/Class;", "forName", "Ljava/lang/Class;",
             {"Ljava/lang/String;"}}, 3U, false},
    };
    reflection_caller.direct_methods.push_back(std::move(reflection_method));
    reflection_builder.AddClass(std::move(reflection_caller));
    const auto reflection_source = birch::dex::DexFile::Parse(
        reflection_builder.Build());
    const auto reflection_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 881199,
      "scope": {"protect": [{"pattern": "Lmodel/**;"}], "keep": []},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "data.reflection_string_encryption": {"enabled": true, "intensity": 1.0}
      }
    })json");
    birch::guard::ReflectionRenamePlan reflection_renames;
    reflection_renames.classes.emplace("Lmodel/Target;", "Lb/x;");
    const auto reflection_lowered = birch::guard::DexModelLowering(
        reflection_config, &reflection_renames).Apply(reflection_source);
    const auto reflection_output = birch::dex::DexFile::Parse(
        reflection_lowered.bytes);
    birch::dex::VerifyDexOrThrow(reflection_output,
                                 birch::dex::VerificationLevel::Full);
    assert(reflection_lowered.encrypted_strings == 1U);
    assert(std::none_of(reflection_output.strings().begin(),
                        reflection_output.strings().end(), [](const auto& item) {
        return item.mutf8 == "model.Target" || item.mutf8 == "b.x";
    }));
    const auto expected_reflection_helper =
        birch::guard::RuntimeStringMethodName("b.x", 881199U);
    bool found_reflection_helper = false;
    for (const auto& method_id : reflection_output.methods()) {
        found_reflection_helper = found_reflection_helper ||
            reflection_output.string(method_id.name_idx) ==
                expected_reflection_helper;
    }
    assert(found_reflection_helper);

    const auto indirect_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 881199,
      "scope": {"protect": [{"pattern": "Lmodel/**;"}], "keep": []},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "reflection.indirect_targets": {"enabled": true, "intensity": 1.0},
        "data.reflection_string_encryption": {"enabled": true, "intensity": 1.0}
      }
    })json");
    const auto indirect_lowered = birch::guard::DexModelLowering(
        indirect_config).Apply(reflection_source);
    assert(indirect_lowered.pass_applications.at(
               "reflection.indirect_targets") == 1U);
    assert(indirect_lowered.pass_applications.at(
               "data.reflection_string_encryption") == 1U);
    const auto indirect_output = birch::dex::DexFile::Parse(
        indirect_lowered.bytes);
    birch::dex::VerifyDexOrThrow(indirect_output,
                                 birch::dex::VerificationLevel::Full);
    bool caller_uses_proxy = false;
    bool proxy_uses_reflection = false;
    for (std::size_t class_index = 0U;
         class_index < indirect_output.classes().size(); ++class_index) {
        const auto owner = indirect_output.descriptor(
            indirect_output.classes()[class_index].class_idx);
        const auto& class_data = indirect_output.class_data(class_index);
        for (const auto& encoded : class_data.direct_methods) {
            const auto code = birch::dex::DecodeCodeItem(
                indirect_output, encoded.code_off);
            for (const auto& instruction : code.instructions) {
                if (instruction.opcode < 0x6eU ||
                    instruction.opcode > 0x78U ||
                    instruction.code_units.size() < 2U) {
                    continue;
                }
                const auto target_index = instruction.code_units[1U];
                if (target_index >= indirect_output.methods().size()) continue;
                const auto& target = indirect_output.methods()[target_index];
                const auto target_owner = indirect_output.descriptor(
                    target.class_idx);
                const auto target_name = indirect_output.string(target.name_idx);
                if (owner == "Lmodel/Reflector;" &&
                    instruction.opcode == 0x71U &&
                    target_owner != "Ljava/lang/Class;") {
                    caller_uses_proxy = true;
                }
                if (owner != "Lmodel/Reflector;" &&
                    target_owner == "Ljava/lang/Class;" &&
                    target_name == "forName") {
                    proxy_uses_reflection = true;
                }
            }
        }
    }
    assert(caller_uses_proxy && proxy_uses_reflection);

    const auto opaque_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 881199,
      "scope": {"protect": [{"pattern": "Lmodel/**;"}], "keep": []},
      "passes": {
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0},
        "predicate.crypto": {"enabled": true, "intensity": 1.0}
      }
    })json");
    const auto opaque_lowered = birch::guard::DexModelLowering(
        opaque_config).Apply(source);
    const auto opaque_output = birch::dex::DexFile::Parse(opaque_lowered.bytes);
    birch::dex::VerifyDexOrThrow(opaque_output,
                                 birch::dex::VerificationLevel::Full);
    assert(opaque_output.classes().size() == source.classes().size() + 1U);
    bool found_stateful_predicate = false;
    for (std::size_t class_index = 0U;
         class_index < opaque_output.classes().size(); ++class_index) {
        const auto owner = opaque_output.descriptor(
            opaque_output.classes()[class_index].class_idx);
        if (owner == "Lmodel/Business;") continue;
        const auto& helper_data = opaque_output.class_data(class_index);
        assert(helper_data.direct_methods.size() == 1U);
        const auto& encoded = helper_data.direct_methods.front();
        assert((encoded.access_flags & 0x0020U) != 0U); // synchronized
        const auto helper_code = birch::dex::DecodeCodeItem(
            opaque_output, encoded.code_off);
        const auto opcode_count = [&](std::uint8_t opcode) {
            return std::count_if(
                helper_code.instructions.begin(), helper_code.instructions.end(),
                [&](const auto& instruction) {
                    return instruction.opcode == opcode;
                });
        };
        assert(opcode_count(0x60U) >= 4); // volatile state read + re-read
        assert(opcode_count(0x67U) == 2); // strategy-specific state publication
        assert(opcode_count(0x39U) == 1); // invariant validation
        assert(std::none_of(
            helper_code.instructions.begin(), helper_code.instructions.end(),
            [](const auto& instruction) {
                return instruction.code_units.size() == 2U &&
                    instruction.code_units[0U] == 0x01dfU &&
                    instruction.code_units[1U] == 0xff00U;
            }));
        found_stateful_predicate = true;
    }
    assert(found_stateful_predicate);
    return 0;
}
