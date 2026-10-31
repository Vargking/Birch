#include "birch/dex/builder.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"
#include "birch/guard/opaque_runtime.h"
#include "birch/guard/pipeline.h"

#include <cassert>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

namespace {

void WriteFile(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
}

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}

} // namespace

int main() {
    birch::dex::DexBuilder builder(38U);

    birch::dex::ClassSpec native_class;
    native_class.descriptor = "Lsample/NativeBridge;";
    native_class.direct_methods.push_back(
        {"nativeEntry", "V", {}, 0x0109U, {}}); // public static native
    native_class.direct_methods.push_back(
        {"helperNativeOwner", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(native_class));

    birch::dex::ClassSpec activity;
    activity.descriptor = "Lsample/Screen;";
    activity.superclass = "Landroid/app/Activity;";
    activity.access_flags = 0x0001U;
    activity.virtual_methods.push_back(
        {"onResume", "V", {}, 0x0001U, {1U, 1U, 0U, {0x000eU}}});
    activity.direct_methods.push_back(
        {"screenHelper", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(activity));

    birch::dex::ClassSpec payload;
    payload.descriptor = "Lsample/Payload;";
    payload.interfaces = {"Ljava/io/Serializable;", "Landroid/os/Parcelable;"};
    payload.static_fields.push_back(
        {"CREATOR", "Landroid/os/Parcelable$Creator;", 0x0019U});
    payload.static_fields.push_back({"serialVersionUID", "J", 0x001aU});
    payload.instance_fields.push_back({"secretPayload", "I", 0x0002U});
    payload.direct_methods.push_back(
        {"writeObject", "V", {"Ljava/io/ObjectOutputStream;"}, 0x0002U,
         {2U, 2U, 0U, {0x000eU}}});
    payload.direct_methods.push_back(
        {"payloadHelper", "V", {}, 0x0009U, {1U, 0U, 0U, {0x000eU}}});
    payload.virtual_methods.push_back(
        {"writeToParcel", "V", {"Landroid/os/Parcel;", "I"}, 0x0001U,
         {3U, 3U, 0U, {0x000eU}}});
    payload.virtual_methods.push_back(
        {"describeContents", "I", {}, 0x0001U,
         {2U, 1U, 0U, {0x0012U, 0x000fU}}});
    builder.AddClass(std::move(payload));

    const auto input_path = std::filesystem::path("birch-runtime-keep-input.dex");
    const auto output_path = std::filesystem::path("birch-runtime-keep-output.dex");
    WriteFile(input_path, builder.Build());

    const auto pipeline = birch::guard::GuardPipeline::FromJson(R"json({
      "schema_version": 1,
      "seed": 77123,
      "scope": {"protect": [{"pattern": "Lsample/**;"}], "keep": []},
      "strength": {"per_method_strategy": true,
                   "randomized_parameters": false,
                   "reproducible_output": true,
                   "anti_automation_profile": false,
                   "target_analysis_cost_weeks": 0},
      "budget": {"max_method_growth_ratio": 32.0,
                 "max_dex_growth_ratio": 16.0},
      "output": {"write_mapping": false, "mapping_file": ""},
      "passes": {
        "rename.classes": {"enabled": true, "intensity": 1.0},
        "rename.methods": {"enabled": true, "intensity": 1.0},
        "rename.fields": {"enabled": true, "intensity": 1.0},
        "predicate.crypto": {"enabled": true, "intensity": 1.0,
                             "max_applications_per_method": 1},
        "cfg.bogus_edges": {"enabled": true, "intensity": 1.0,
                             "max_applications_per_method": 1},
        "cfg.exception_dispatch": {"enabled": true, "intensity": 1.0,
                                   "max_applications_per_method": 1}
      }
    })json");
    // This tiny fixture legitimately cannot fit the full 1024-state bogus
    // graph plus runtime helpers in 16x. Keep the budget failure as a regression.
    bool rejected_growth = false;
    try {
        pipeline.TransformDex(input_path, output_path);
    } catch (const std::runtime_error& error) {
        rejected_growth = std::string(error.what()).find(
            "max_dex_growth_ratio") != std::string::npos;
    }
    assert(rejected_growth);
    auto runtime_config = pipeline.config();
    runtime_config.budget.max_dex_growth_ratio = 32.0;
    birch::guard::GuardPipeline::FromConfig(std::move(runtime_config))
        .TransformDex(input_path, output_path);

    const auto dex = birch::dex::DexFile::Parse(ReadFile(output_path));
    assert(birch::dex::VerifyDex(dex, birch::dex::VerificationLevel::Full).ok);
    bool found_native = false;
    bool found_payload = false;
    bool found_renamed_activity = false;
    for (std::size_t class_index = 0U; class_index < dex.classes().size(); ++class_index) {
        const auto owner = dex.descriptor(dex.classes()[class_index].class_idx);
        const auto& data = dex.class_data(class_index);
        std::set<std::string> methods;
        for (const auto* group : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& encoded : *group) {
                methods.insert(dex.string(dex.methods().at(encoded.method_idx).name_idx));
            }
        }
        std::set<std::string> fields;
        for (const auto* group : {&data.static_fields, &data.instance_fields}) {
            for (const auto& encoded : *group) {
                fields.insert(dex.string(dex.fields().at(encoded.field_idx).name_idx));
            }
        }
        if (owner == "Lsample/NativeBridge;") {
            found_native = true;
            assert(methods.contains("nativeEntry"));
            assert(!methods.contains("helperNativeOwner"));
        } else if (owner == "Lsample/Payload;") {
            found_payload = true;
            assert(methods.contains("writeObject"));
            assert(methods.contains("writeToParcel"));
            assert(methods.contains("describeContents"));
            assert(!methods.contains("payloadHelper"));
            assert(fields.contains("CREATOR"));
            assert(fields.contains("serialVersionUID"));
            assert(!fields.contains("secretPayload"));
            const auto describe = std::find_if(
                data.virtual_methods.begin(), data.virtual_methods.end(),
                [&](const auto& encoded) {
                    return dex.string(dex.methods().at(encoded.method_idx).name_idx) ==
                           "describeContents";
                });
            assert(describe != data.virtual_methods.end());
            const auto code = birch::dex::DecodeCodeItem(dex, describe->code_off);
            assert(std::any_of(code.instructions.begin(),
                               code.instructions.end(), [](const auto& item) {
                return item.opcode == 0x38U || item.opcode == 0x39U;
            }));
            assert(code.tries.size() == 1U);
            assert(std::any_of(code.instructions.begin(), code.instructions.end(),
                               [&](const auto& instruction) {
                return instruction.offset == code.tries.front().start_address;
            }));
        } else if (owner.starts_with("Lb/") && methods.contains("onResume")) {
            found_renamed_activity = true;
            assert(methods.contains("onResume"));
            assert(!methods.contains("screenHelper"));
        }
    }
    assert(found_native && found_payload && found_renamed_activity);
    const auto exception_method_name =
        birch::guard::RuntimeExceptionMethodName(77123U);
    assert(std::none_of(
        dex.methods().begin(), dex.methods().end(), [&](const auto& method) {
            return dex.string(method.name_idx) == exception_method_name;
        }));
    for (std::size_t slot = 0U;
         slot < birch::guard::kRuntimeExceptionStateFields; ++slot) {
        const auto field_name =
            birch::guard::RuntimeExceptionFieldName(77123U, slot);
        assert(std::none_of(
            dex.fields().begin(), dex.fields().end(), [&](const auto& field) {
                return dex.string(field.name_idx) == field_name;
            }));
    }
    const auto opaque_method_name =
        birch::guard::RuntimeOpaqueMethodName(77123U, 10U);
    assert(std::none_of(
        dex.methods().begin(), dex.methods().end(), [&](const auto& method) {
            return dex.string(method.name_idx) == opaque_method_name;
        }));
    for (std::size_t shard = 0U;
         shard < birch::guard::kRuntimeOpaqueClassShards; ++shard) {
        for (std::size_t slot = 0U;
             slot < birch::guard::kRuntimeOpaqueStateFields; ++slot) {
            const auto field_name = birch::guard::RuntimeOpaqueFieldName(
                77123U, shard, slot);
            assert(std::none_of(
                dex.fields().begin(), dex.fields().end(),
                [&](const auto& field) {
                    return dex.string(field.name_idx) == field_name;
                }));
        }
    }
    bool protected_runtime_helper = false;
    for (std::size_t class_index = 0U;
         class_index < dex.classes().size(); ++class_index) {
        const auto& data = dex.class_data(class_index);
        for (const auto& encoded : data.direct_methods) {
            if ((encoded.access_flags & 0x0020U) == 0U ||
                encoded.code_off == 0U) {
                continue;
            }
            const auto helper_code = birch::dex::DecodeCodeItem(
                dex, encoded.code_off);
            protected_runtime_helper = protected_runtime_helper ||
                std::any_of(helper_code.instructions.begin(),
                            helper_code.instructions.end(),
                            [](const auto& instruction) {
                                return instruction.opcode == 0x2cU;
                            });
        }
    }
    assert(protected_runtime_helper);

    std::filesystem::remove(input_path);
    std::filesystem::remove(output_path);
    return 0;
}
