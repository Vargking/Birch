#include "birch/dex/builder.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/verifier.h"
#include "birch/guard/model_lowering.h"
#include "birch/guard/pipeline.h"

#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace {

birch::dex::MethodSpec ConstantMethod(std::string name, std::int32_t value) {
    birch::dex::MethodSpec method;
    method.name = std::move(name);
    method.return_type = "I";
    method.access_flags = 0x0009U;
    method.body.registers_size = 1U;
    method.body.code_units = {
        static_cast<std::uint16_t>(0x0012U | (0U << 8U) | ((value & 0x0f) << 12U)),
        0x000fU,
    };
    return method;
}

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}

std::string BuildConfigJson(bool build_randomization, bool per_method_randomization) {
    std::ostringstream stream;
    stream << R"json({
      "schema_version": 1,
      "seed": 912345,
      "scope": {"protect": [{"pattern": "Lsample/**;"}], "keep": []},
      "budget": {
        "max_dex_growth_ratio": 16.0,
        "max_method_growth_ratio": 32.0,
        "max_added_blocks_per_method": 1024,
        "max_analysis_blocks_per_method": 16384
      },
      "strength": {
        "per_method_strategy": true,
        "randomized_parameters": true,
        "reproducible_output": true,
        "anti_automation_profile": true,
        "target_analysis_cost_weeks": 0
      },
      "output": {"write_mapping": false, "mapping_file": ""},
      "passes": {
        "rename.classes": {"enabled": true, "intensity": 1.0},
        "rename.methods": {"enabled": false, "intensity": 0.0},
        "rename.fields": {"enabled": false, "intensity": 0.0},
        "rename.parameters": {"enabled": false, "intensity": 0.0},
        "rename.packages": {"enabled": false, "intensity": 0.0},
        "rename.overload_induction": {"enabled": false, "intensity": 0.0},
        "structure.method_outlining": {"enabled": true, "intensity": 1.0},
        "structure.method_splitting": {"enabled": true, "intensity": 1.0},
        "structure.proxy_stubs": {"enabled": true, "intensity": 1.0},
        "cfg.tail_recursion": {"enabled": true, "intensity": 1.0},
        "strength.per_method_randomization": {"enabled": )json";
    stream << (per_method_randomization ? "true" : "false");
    stream << R"json(, "intensity": 1.0},
        "strength.build_parameter_randomization": {"enabled": )json";
    stream << (build_randomization ? "true" : "false");
    stream << R"json(, "intensity": 1.0},
        "anti_analysis.debug_info_removal": {"enabled": false, "intensity": 1.0}
      }
    })json";
    return stream.str();
}

} // namespace

int main() {
    using namespace birch;

    dex::DexBuilder builder(38U);
    dex::ClassSpec klass;
    klass.descriptor = "Lsample/Choice;";
    klass.direct_methods.push_back(ConstantMethod("first", 1));
    klass.direct_methods.push_back(ConstantMethod("second", 2));
    builder.AddClass(std::move(klass));

    const auto source = dex::DexFile::Parse(builder.Build());
    dex::VerifyDexOrThrow(source, dex::VerificationLevel::Full);

    const auto build_input = std::filesystem::path("strength-randomization-input.dex");
    const auto build_off = std::filesystem::path("strength-randomization-off.dex");
    const auto build_on = std::filesystem::path("strength-randomization-on.dex");
    {
        std::ofstream output(build_input, std::ios::binary);
        const auto bytes = source.Write();
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }

    const auto pipeline_off = guard::GuardPipeline::FromJson(
        BuildConfigJson(false, false));
    const auto pipeline_on = guard::GuardPipeline::FromJson(
        BuildConfigJson(true, false));
    pipeline_off.TransformDex(build_input, build_off);
    pipeline_on.TransformDex(build_input, build_on);

    const auto off_bytes = ReadFile(build_off);
    const auto on_bytes = ReadFile(build_on);
    assert(off_bytes != on_bytes);
    const auto off_dex = dex::DexFile::Parse(off_bytes);
    const auto on_dex = dex::DexFile::Parse(on_bytes);
    dex::VerifyDexOrThrow(off_dex, dex::VerificationLevel::Full);
    dex::VerifyDexOrThrow(on_dex, dex::VerificationLevel::Full);
    assert(off_dex.descriptor(off_dex.classes().front().class_idx) !=
           on_dex.descriptor(on_dex.classes().front().class_idx));

    const auto model_off = guard::DexModelLowering(
        guard::GuardConfig::Parse(BuildConfigJson(false, false))).Apply(source);
    const auto model_on = guard::DexModelLowering(
        guard::GuardConfig::Parse(BuildConfigJson(false, true))).Apply(source);
    assert(model_off.bytes != model_on.bytes);
    dex::VerifyDexOrThrow(dex::DexFile::Parse(model_off.bytes),
                          dex::VerificationLevel::Full);
    dex::VerifyDexOrThrow(dex::DexFile::Parse(model_on.bytes),
                          dex::VerificationLevel::Full);

    std::filesystem::remove(build_input);
    std::filesystem::remove(build_off);
    std::filesystem::remove(build_on);
    return 0;
}
