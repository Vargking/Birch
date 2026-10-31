#include "birch/guard/fake.h"
#include "birch/guard/model_lowering.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/code.h"
#include "birch/dex/verifier.h"

#include <cassert>
#include <limits>
#include <stdexcept>

namespace {
void CheckDensity() {
    // Method zero is always the density-controlled static-body variant.
    for (const auto density : {0.0, 1.0}) {
        birch::guard::FakeClassOptions options;
        options.methods_per_class = 1U;
        options.density = density;
        const auto dex = birch::dex::DexFile::Parse(birch::guard::BuildFakeDex(options));
        bool found = false;
        for (const auto& method : dex.class_data(0U).direct_methods) {
            if (!dex.string(dex.methods()[method.method_idx].name_idx).starts_with("m")) continue;
            found = true;
            const auto code = birch::dex::DecodeCodeItem(dex, method.code_off);
            bool has_invoke = false;
            for (const auto& instruction : code.instructions)
                has_invoke |= instruction.opcode == 0x71U;
            assert(has_invoke == (density == 1.0));
        }
        assert(found);
    }
    for (const auto density : {-1.0, 1.1, std::numeric_limits<double>::infinity(),
                               std::numeric_limits<double>::quiet_NaN()}) {
        birch::guard::FakeClassOptions options;
        options.density = density;
        bool rejected = false;
        try { (void)birch::guard::BuildFakeDex(options); }
        catch (const std::invalid_argument&) { rejected = true; }
        assert(rejected);
    }
}
}

int main() {
    CheckDensity();
    const auto bytes = birch::guard::BuildFakeDex({"Lx/fake/", 4U, 5U, 99U});
    const auto dex = birch::dex::DexFile::Parse(bytes);
    assert(dex.classes().size() == 4U);
    assert(dex.methods().size() >= 24U);
    assert(!dex.strings().empty());
    assert(dex.VerifyChecksums());
    bool saw_instance_field = false;
    bool saw_virtual_body = false;
    bool saw_string_noise = false;
    for (std::size_t class_index = 0U; class_index < dex.classes().size(); ++class_index) {
        const auto owner = dex.descriptor(dex.classes()[class_index].class_idx);
        assert(owner.starts_with("Lx/fake/C"));
        assert(owner.find("C0;") == std::string::npos);
        const auto& data = dex.class_data(class_index);
        saw_instance_field = saw_instance_field || !data.instance_fields.empty();
        saw_virtual_body = saw_virtual_body || !data.virtual_methods.empty();
    }
    for (const auto& value : dex.strings()) {
        saw_string_noise = saw_string_noise || value.mutf8.starts_with("z");
    }
    assert(saw_instance_field && saw_virtual_body && saw_string_noise);

    const auto invoke_bytes = birch::guard::BuildFakeDex({"Lx/fake/", 1U, 1U, 99U, true});
    const auto invoke_dex = birch::dex::DexFile::Parse(invoke_bytes);
    const auto& invoke_data = invoke_dex.class_data(0U);
    bool saw_fake_target = false;
    bool saw_real_target = false;
    for (const auto& encoded : invoke_data.direct_methods) {
        if (encoded.code_off == 0U) continue;
        const auto invoke_code = birch::dex::DecodeCodeItem(
            invoke_dex, encoded.code_off);
        for (const auto& instruction : invoke_code.instructions) {
            if (instruction.opcode != 0x71U) continue;
            const auto method_index = instruction.code_units.at(1U);
            const auto key = invoke_dex.method_key(method_index);
            saw_fake_target |= key.starts_with("Lx/fake/");
            saw_real_target |= key.starts_with("Ljava/lang/System;->gc");
        }
    }
    assert(saw_fake_target && saw_real_target);

    birch::guard::FakeClassOptions mixed_options;
    mixed_options.package_prefix = "Lx/fake/";
    mixed_options.class_count = 2U;
    mixed_options.methods_per_class = 2U;
    mixed_options.seed = 7U;
    mixed_options.invoke_real_method = true;
    mixed_options.real_targets.push_back(
        {"Lreal/Business;", "touch", "I", {"Ljava/lang/String;", "J", "I"}});
    const auto mixed_dex = birch::dex::DexFile::Parse(
        birch::guard::BuildFakeDex(mixed_options));
    bool saw_business = false;
    for (const auto& method : mixed_dex.methods()) {
        saw_business |= mixed_dex.descriptor(method.class_idx) == "Lreal/Business;" &&
                        mixed_dex.string(method.name_idx) == "touch";
    }
    assert(saw_business);
    mixed_options.dex_version = 37U;
    const auto versioned = birch::dex::DexFile::Parse(
        birch::guard::BuildFakeDex(mixed_options));
    assert(versioned.version() == 37U);

    // A production fake shard must exercise heterogeneous model transforms,
    // rather than becoming a large set of identical static-call templates.
    birch::guard::FakeClassOptions diverse_options;
    diverse_options.package_prefix = "Lx/fake/";
    diverse_options.class_count = 32U;
    diverse_options.methods_per_class = 6U;
    diverse_options.seed = 77123U;
    diverse_options.invoke_real_method = true;
    const auto diverse = birch::dex::DexFile::Parse(
        birch::guard::BuildFakeDex(diverse_options));
    const auto diverse_config = birch::guard::GuardConfig::Parse(R"json({
      "seed": 77123,
      "scope": {"protect": [{"pattern": "Lx/fake/**;"}], "keep": []},
      "passes": {
        "structure.class_merging": {"enabled": true, "intensity": 1.0},
        "structure.interface_abstract_conversion": {"enabled": true, "intensity": 1.0},
        "structure.method_inlining": {"enabled": true, "intensity": 1.0},
        "data.array_virtualization": {"enabled": true, "intensity": 1.0},
        "data.array_splitting": {"enabled": true, "intensity": 1.0},
        "data.string_encryption": {"enabled": true, "intensity": 1.0},
        "data.reflection_string_encryption": {"enabled": true, "intensity": 1.0},
        "reflection.indirect_targets": {"enabled": true, "intensity": 1.0},
        "loading.encrypted_paths": {"enabled": true, "intensity": 1.0}
      }
    })json");
    const auto lowered = birch::guard::DexModelLowering(
        diverse_config).Apply(diverse);
    assert(lowered.merged_classes > 0U);
    assert(lowered.converted_classes > 0U);
    assert(lowered.inlined_calls > 0U);
    assert(lowered.virtualized_arrays > 0U);
    assert(lowered.split_arrays > 0U);
    assert(lowered.pass_applications.at("reflection.indirect_targets") > 0U);
    assert(lowered.pass_applications.at("data.reflection_string_encryption") > 0U);
    assert(lowered.pass_applications.at("loading.encrypted_paths") > 0U);
    birch::dex::VerifyDexOrThrow(
        birch::dex::DexFile::Parse(lowered.bytes),
        birch::dex::VerificationLevel::Full);
    return 0;
}
