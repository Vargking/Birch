#include "birch/dex/cloner.h"
#include "birch/dex/code.h"
#include "birch/dex/type_analysis.h"
#include "birch/dex/verifier.h"
#include "birch/guard/dex_lowering.h"
#include "birch/guard/model_lowering.h"
#include "birch/guard/zip.h"
#include "birch/io/file.h"
#include "birch/utils/hash.h"

#include <filesystem>
#include <charconv>
#include <iostream>
#include <stdexcept>
#include <set>

// Isolate an application class without rewriting its bodies or parameter types.
// Kept outside the release path so failed input and intermediate DEXes can be
// inspected without weakening any production verification gate.
int main(int argc, char** argv) try {
    if (argc != 5 && argc != 6) throw std::runtime_error(
        "usage: BirchLoweringProbe config apk dex-entry class-descriptor [materialize|seed]\n"
        "       BirchLoweringProbe config apk dex-entry --find-method substring");
    const bool find_method = std::string_view(argv[4]) == "--find-method";
    if (find_method && argc != 6) throw std::runtime_error("invalid probe mode");
    auto config = birch::guard::GuardConfig::Parse(birch::io::ReadTextFile(argv[1]));
    const bool materialize = !find_method && argc == 6 &&
        std::string_view(argv[5]) == "materialize";
    if (!find_method && argc == 6 && !materialize) {
        const std::string_view seed(argv[5]);
        const auto parsed = std::from_chars(seed.data(), seed.data() + seed.size(), config.seed);
        if (parsed.ec != std::errc{} || parsed.ptr != seed.data() + seed.size())
            throw std::runtime_error("invalid probe seed");
    }
    const auto archive = birch::guard::ZipArchive::Read(argv[2]);
    const auto* entry = archive.Find(argv[3]);
    if (!entry) throw std::runtime_error("missing DEX entry");
    const auto input = birch::dex::DexFile::Parse(entry->data);
    if (find_method) {
        for (std::uint32_t i = 0U; i < input.methods().size(); ++i) {
            const auto key = input.method_key(i);
            if (key.find(argv[5]) != std::string::npos) std::cout << key << '\n';
        }
        return 0;
    }
    const auto source = birch::dex::DexFile::Parse(input.StripDebugInfo());
    birch::dex::DexClassCloner cloner(source);
    birch::dex::DexBuilder builder(source.version());
    bool found = false;
    for (std::size_t c = 0; c < source.classes().size(); ++c) {
        if (source.descriptor(source.classes()[c].class_idx) != argv[4]) continue;
        builder.AddClass(cloner.Clone(c));
        found = true;
    }
    if (!found) throw std::runtime_error("missing class");
    const auto isolated = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(isolated, birch::dex::VerificationLevel::Full);
    const auto modeled = birch::guard::DexModelLowering(config).Apply(isolated);
    const auto output_dir = std::filesystem::path("out/lowering-probe") /
        (std::filesystem::path(argv[3]).stem().string() + '-' +
         std::to_string(birch::utils::StableHash64(argv[4], config.seed)));
    std::filesystem::create_directories(output_dir);
    birch::io::WriteBinaryFile(output_dir / "model.dex", modeled.bytes);
    const auto model = birch::dex::DexFile::Parse(modeled.bytes);
    birch::dex::VerifyDexOrThrow(model, birch::dex::VerificationLevel::Full);
    // Mirror the production pipeline: generated companion names deliberately
    // use opaque namespaces and cannot be recognized by a prefix heuristic.
    std::set<std::string, std::less<>> input_owners;
    for (const auto& klass : isolated.classes()) input_owners.insert(isolated.descriptor(klass.class_idx));
    for (const auto& klass : model.classes()) {
        const auto owner = model.descriptor(klass.class_idx);
        if (!input_owners.contains(owner)) config.scope.protect.push_back({owner, true, true, true});
    }
    if (materialize) {
        for (const auto id : {"cfg.flattening", "cfg.nested_flattening",
             "cfg.multi_state_dispatch", "cfg.bogus_edges", "cfg.loop_state_machine",
             "cfg.condition_expansion", "cfg.conditional_nesting", "cfg.table_dispatch",
             "cfg.indirect_dispatch", "cfg.mixed_ps_ss_if", "cfg.callback_style",
             "cfg.dead_blocks", "cfg.block_reordering", "anti_analysis.path_explosion",
             "strength.analysis_cost_budget"}) config.passes.at(id).enabled = false;
        config.strength.anti_automation_profile = false;
        config.strength.target_analysis_cost_weeks = 0U;
    }
    for (std::size_t c = 0; c < model.classes().size(); ++c) {
        const auto& data = model.class_data(c);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (!method.code_off) continue;
                const auto code = birch::dex::DecodeCodeItem(model, method.code_off);
                std::cout << model.method_key(method.method_idx) << " registers="
                          << code.registers_size << " inputs=" << code.ins_size
                          << " units=" << code.insns.size();
                std::size_t payload_units = 0U;
                for (const auto& instruction : code.instructions)
                    if (instruction.kind == birch::dex::InstructionKind::Payload)
                        payload_units += instruction.width;
                std::cout << " payload=" << payload_units << '\n';
            }
        }
    }
    const auto lowered = birch::guard::DexCodeLowering(config).Apply(model);
    const auto output = birch::dex::DexFile::Parse(lowered.bytes);
    birch::dex::VerifyDexOrThrow(output, birch::dex::VerificationLevel::Full);
    std::size_t largest = 0U;
    std::string largest_key;
    for (std::size_t c = 0U; c < output.classes().size(); ++c) {
        const auto& data = output.class_data(c);
        for (const auto* methods : {&data.direct_methods, &data.virtual_methods}) {
            for (const auto& method : *methods) {
                if (!method.code_off) continue;
                const auto code = birch::dex::DecodeCodeItem(output, method.code_off);
                if (code.insns.size() > largest) {
                    largest = code.insns.size();
                    largest_key = output.method_key(method.method_idx);
                }
            }
        }
    }
    std::cout << "seed=" << config.seed << " largest=" << largest << ' ' << largest_key << '\n';
    birch::io::WriteBinaryFile(output_dir / "output.dex", lowered.bytes);
    std::cout << "Isolated class passed model and code lowering: "
              << std::filesystem::absolute(output_dir).string() << '\n';
    return 0;
} catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
