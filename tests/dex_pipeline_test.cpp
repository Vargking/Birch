#include "birch/dex/builder.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"
#include "birch/guard/pipeline.h"

#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <set>
#include <vector>

int main() {
    birch::dex::DexBuilder builder(38U);
    birch::dex::ClassSpec klass;
    klass.descriptor = "Lsample/Input;";
    klass.direct_methods.push_back({"run", "V", {}, 0x0009U,
                                    {1U, 0U, 0U, {0x000eU}}});
    klass.direct_methods.push_back({"clash", "V", {}, 0x0009U,
                                    {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(klass));
    birch::dex::ClassSpec second;
    second.descriptor = "Lsample/Second;";
    second.direct_methods.push_back({"other", "V", {}, 0x0009U,
                                     {1U, 0U, 0U, {0x000eU}}});
    builder.AddClass(std::move(second));
    birch::dex::ClassSpec parent;
    parent.descriptor = "Lsample/Parent;";
    parent.virtual_methods.push_back({"alpha", "V", {}, 0x0001U,
                                      {1U, 1U, 0U, {0x000eU}}});
    builder.AddClass(std::move(parent));
    birch::dex::ClassSpec child;
    child.descriptor = "Lsample/Child;";
    child.superclass = "Lsample/Parent;";
    child.virtual_methods.push_back({"beta", "V", {}, 0x0001U,
                                     {1U, 1U, 0U, {0x000eU}}});
    builder.AddClass(std::move(child));

    const auto input_path = std::filesystem::path("birch-dex-pipeline-input.dex");
    const auto output_path = std::filesystem::path("birch-dex-pipeline-output.dex");
    {
        const auto bytes = builder.Build();
        std::ofstream output(input_path, std::ios::binary);
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }

    const auto pipeline = birch::guard::GuardPipeline::FromJson(R"json({
      "schema_version": 1,
      "seed": 42,
      "scope": {"protect": [{"pattern": "Lsample/**;"}], "keep": []},
      "rename": {"package_prefix": "b", "overload_methods": true, "rename_source_files": true},
      "resources": {"rename_files": false, "rename_names": false},
      "output": {"write_mapping": false, "mapping_file": ""},
      "passes": {
        "rename.classes": {"enabled": true, "intensity": 1.0},
        "rename.overload_induction": {"enabled": true, "intensity": 1.0},
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0}
      }
    })json");
    pipeline.TransformDex(input_path, output_path);

    std::vector<std::uint8_t> output_bytes;
    {
        std::ifstream input(output_path, std::ios::binary);
        output_bytes.assign(std::istreambuf_iterator<char>(input), {});
    }
    const auto dex = birch::dex::DexFile::Parse(output_bytes);
    assert(birch::dex::VerifyDex(dex, birch::dex::VerificationLevel::Full).ok);
    std::set<std::string> method_names;
    std::size_t method_count = 0U;
    bool all_flat_packages = true;
    std::string inherited_name;
    std::string descendant_name;
    for (std::size_t class_index = 0U; class_index < dex.classes().size(); ++class_index) {
        const auto descriptor = dex.descriptor(
            dex.classes()[class_index].class_idx);
        assert(descriptor.starts_with("Lb/"));
        all_flat_packages = all_flat_packages &&
            std::count(descriptor.begin(), descriptor.end(), '/') == 1;
        for (const auto& method : dex.class_data(class_index).direct_methods) {
            method_names.insert(dex.string(dex.methods()[method.method_idx].name_idx));
            ++method_count;
        }
        if (dex.classes()[class_index].superclass_idx != 0xffffffffU &&
            dex.descriptor(dex.classes()[class_index].superclass_idx) !=
                "Ljava/lang/Object;" &&
            !dex.class_data(class_index).virtual_methods.empty()) {
            descendant_name = dex.string(dex.methods().at(
                dex.class_data(class_index).virtual_methods.front().method_idx).name_idx);
            const auto parent_descriptor = dex.descriptor(
                dex.classes()[class_index].superclass_idx);
            for (std::size_t candidate = 0U;
                 candidate < dex.classes().size(); ++candidate) {
                if (dex.descriptor(dex.classes()[candidate].class_idx) ==
                        parent_descriptor &&
                    !dex.class_data(candidate).virtual_methods.empty()) {
                    inherited_name = dex.string(dex.methods().at(
                        dex.class_data(candidate).virtual_methods.front().method_idx).name_idx);
                }
            }
        }
    }
    assert(method_count == 3U);
    assert(method_names.size() == 2U); // one overload color is reused across owners
    assert(all_flat_packages);
    assert(!inherited_name.empty() && !descendant_name.empty());
    assert(inherited_name != descendant_name);

    std::filesystem::remove(input_path);
    std::filesystem::remove(output_path);
    return 0;
}
