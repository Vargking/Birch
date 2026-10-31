#include "birch/dex/cfg.h"
#include "birch/dex/code.h"
#include "birch/dex/dex_file.h"
#include "birch/dex/ir.h"
#include "birch/dex/partition.h"
#include "birch/dex/program.h"
#include "birch/dex/verifier.h"
#include "birch/guard/apk.h"
#include "birch/guard/zip.h"
#include "birch/io/apk_entries.h"
#include "birch/io/file.h"
#include "tools/diagnostic_options.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <vector>

namespace {

std::vector<std::uint16_t> Mutf8Units(std::string_view value) {
    std::vector<std::uint16_t> units;
    for (std::size_t cursor = 0U; cursor < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[cursor]);
        std::uint32_t code_unit = 0U;
        std::size_t width = 0U;
        if (first <= 0x7fU) {
            code_unit = first;
            width = 1U;
        } else if (first >= 0xc0U && first <= 0xdfU) {
            code_unit = first & 0x1fU;
            width = 2U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            code_unit = first & 0x0fU;
            width = 3U;
        } else {
            throw std::runtime_error("invalid MUTF-8 leading byte");
        }
        if (cursor + width > value.size()) {
            throw std::runtime_error("truncated MUTF-8 sequence");
        }
        for (std::size_t index = 1U; index < width; ++index) {
            const auto next = static_cast<std::uint8_t>(value[cursor + index]);
            if ((next & 0xc0U) != 0x80U) {
                throw std::runtime_error("invalid MUTF-8 continuation byte");
            }
            code_unit = (code_unit << 6U) | (next & 0x3fU);
        }
        units.push_back(static_cast<std::uint16_t>(code_unit));
        cursor += width;
    }
    return units;
}

int PartitionDirectory(const std::filesystem::path& directory) {
    std::vector<std::filesystem::path> paths;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file() &&
            birch::io::IsDexEntryName(entry.path().filename().string())) {
            paths.push_back(entry.path());
        }
    }
    std::sort(paths.begin(), paths.end(), [](const auto& left, const auto& right) {
        return birch::io::DexEntryOrdinal(left.filename().string()) <
               birch::io::DexEntryOrdinal(right.filename().string());
    });
    std::vector<birch::dex::DexInput> inputs;
    inputs.reserve(paths.size());
    for (const auto& path : paths) {
        inputs.push_back({path.filename().string(), birch::io::ReadBinaryFile(path)});
    }
    const auto program = birch::dex::DexProgram::Parse(std::move(inputs));
    birch::dex::PartitionOptions options;
    const auto partitions = birch::dex::PartitionProgram(program, options);
    std::cout << "input dex files: " << program.dex_count() << '\n'
              << "output partitions: " << partitions.size() << '\n';
    for (std::size_t i = 0; i < partitions.size(); ++i) {
        const auto& footprint = partitions[i].footprint;
        std::cout << "partition " << (i + 1U)
                  << ": classes=" << partitions[i].classes.size()
                  << " strings=" << footprint.strings.size()
                  << " types=" << footprint.types.size()
                  << " protos=" << footprint.protos.size()
                  << " fields=" << footprint.fields.size()
                  << " methods=" << footprint.methods.size()
                  << " call-sites=" << footprint.call_sites.size()
                  << " method-handles=" << footprint.method_handles.size() << '\n';
    }
    return 0;
}

int InspectApk(const std::filesystem::path& path) {
    const auto archive = birch::guard::ZipArchive::Read(path);
    const auto inspection = birch::guard::InspectApk(archive);
    std::cout << "APK entries: " << inspection.entries.size() << '\n'
              << "DEX files: " << inspection.dex_count << '\n'
              << "Manifest files: " << inspection.manifest_count << '\n'
              << "Resource tables: " << inspection.resources_count << '\n';
    return 0;
}

int AuditCff(const std::filesystem::path& path) {
    const auto dex = birch::dex::DexFile::Parse(birch::io::ReadBinaryFile(path));
    std::size_t single_level_b_classes = 0U;
    std::size_t nested_b_classes = 0U;
    std::size_t visible_fake_classes = 0U;
    for (const auto& definition : dex.classes()) {
        const auto descriptor = dex.descriptor(definition.class_idx);
        if (descriptor.starts_with("Lb/")) {
            const auto nested = descriptor.find('/', 3U) != std::string::npos;
            nested ? ++nested_b_classes : ++single_level_b_classes;
        }
        if (descriptor.starts_with("Lx/") ||
            descriptor.find("birch_fake") != std::string::npos) {
            ++visible_fake_classes;
        }
    }
    std::size_t code_items = 0U;
    std::size_t dispatcher_methods = 0U;
    std::size_t missing_dispatchers = 0U;
    std::size_t total_cases = 0U;
    std::size_t total_unique_targets = 0U;
    std::size_t min_cases = std::numeric_limits<std::size_t>::max();
    std::size_t max_cases = 0U;
    std::size_t min_unique_targets = std::numeric_limits<std::size_t>::max();
    std::size_t max_unique_targets = 0U;
    std::size_t total_code_units = 0U;
    std::size_t max_code_units = 0U;
    std::uint32_t max_dispatcher_offset = 0U;
    std::size_t executable_nops = 0U;
    for (std::size_t class_index = 0U;
         class_index < dex.classes().size(); ++class_index) {
        const auto& data = dex.class_data(class_index);
        const auto audit = [&](const auto& methods) {
            for (const auto& method : methods) {
                if (method.code_off == 0U) continue;
                ++code_items;
                const auto code = birch::dex::DecodeCodeItem(dex, method.code_off);
                total_code_units += code.insns.size();
                max_code_units = std::max(max_code_units, code.insns.size());
                for (const auto& instruction : code.instructions) {
                    if (instruction.kind != birch::dex::InstructionKind::Payload &&
                        instruction.opcode == 0U) {
                        ++executable_nops;
                    }
                }
                const auto first_switch = std::find_if(
                    code.instructions.begin(), code.instructions.end(),
                    [](const auto& instruction) {
                        return instruction.kind ==
                               birch::dex::InstructionKind::Switch;
                    });
                if (first_switch == code.instructions.end()) {
                    ++missing_dispatchers;
                    continue;
                }
                ++dispatcher_methods;
                const auto cases = first_switch->targets.size();
                const std::set<std::uint32_t> unique_targets(
                    first_switch->targets.begin(), first_switch->targets.end());
                total_cases += cases;
                total_unique_targets += unique_targets.size();
                min_cases = std::min(min_cases, cases);
                max_cases = std::max(max_cases, cases);
                min_unique_targets = std::min(
                    min_unique_targets, unique_targets.size());
                max_unique_targets = std::max(
                    max_unique_targets, unique_targets.size());
                max_dispatcher_offset = std::max(
                    max_dispatcher_offset, first_switch->offset);
            }
        };
        audit(data.direct_methods);
        audit(data.virtual_methods);
    }
    std::cout << "code items: " << code_items << '\n'
              << "entry dispatcher methods: " << dispatcher_methods << '\n'
              << "missing entry dispatcher: " << missing_dispatchers << '\n'
              << "single-level Lb classes: " << single_level_b_classes << '\n'
              << "nested Lb classes: " << nested_b_classes << '\n'
              << "visible fake-package classes: " << visible_fake_classes << '\n'
              << "executable nop instructions: " << executable_nops << '\n';
    if (dispatcher_methods != 0U) {
        std::cout << "first-switch cases min/avg/max: "
                  << min_cases << '/'
                  << (total_cases / dispatcher_methods) << '/'
                  << max_cases << '\n'
                  << "first-switch unique targets min/avg/max: "
                  << min_unique_targets << '/'
                  << (total_unique_targets / dispatcher_methods) << '/'
                  << max_unique_targets << '\n'
                  << "code units avg/max: "
                  << (total_code_units / code_items) << '/'
                  << max_code_units << '\n'
                  << "maximum first-switch offset: "
                  << max_dispatcher_offset << " code units\n";
    }
    return missing_dispatchers == 0U ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    using birch::cli::DiagnosticCommand;
    std::vector<std::string_view> arguments;
    for (int index = 1; index < argc; ++index) arguments.emplace_back(argv[index]);
    // Catch argument errors separately from std::invalid_argument raised by a
    // reader/verifier. The latter are input failures, not usage failures.
    std::optional<birch::cli::DiagnosticOptions> parsed;
    try {
        parsed.emplace(birch::cli::DiagnosticOptions::Parse(arguments));
    } catch (const std::invalid_argument& error) {
        std::cerr << "Birch: " << error.what() << '\n';
        birch::cli::DiagnosticOptions::PrintUsage(std::cerr);
        return 2;
    }
    try {
        const auto command = parsed->command();
        const auto& input = parsed->input();
        if (command == DiagnosticCommand::Help) {
            birch::cli::DiagnosticOptions::PrintUsage(std::cout);
            return 0;
        }
        if (command == DiagnosticCommand::Partition) return PartitionDirectory(input);
        if (command == DiagnosticCommand::InspectApk) return InspectApk(input);
        const auto bytes = birch::io::ReadBinaryFile(input);
        const auto dex = birch::dex::DexFile::Parse(bytes);
        std::cout << "DEX version: " << static_cast<unsigned>(dex.version()) << '\n'
                  << "file size: " << dex.header().file_size << '\n'
                  << "strings: " << dex.strings().size() << '\n'
                  << "types: " << dex.types().size() << '\n'
                  << "protos: " << dex.protos().size() << '\n'
                  << "fields: " << dex.fields().size() << '\n'
                  << "methods: " << dex.methods().size() << '\n'
                  << "classes: " << dex.classes().size() << '\n';
        if (command == DiagnosticCommand::Map) {
            for (const auto& item : dex.map()) std::cout << "type=0x" << std::hex << item.type << std::dec << " size=" << item.size << " offset=0x" << std::hex << item.offset << std::dec << '\n';
        }
        if (command == DiagnosticCommand::Verify) {
            std::cout << "checksums: " << (dex.VerifyChecksums() ? "ok" : "invalid") << '\n'
                      << "canonical-order: " << (dex.VerifyCanonicalOrder() ? "ok" : "invalid") << '\n';
            auto ordered_strings = true;
            for (std::size_t i = 1; i < dex.strings().size(); ++i) {
                ordered_strings &= Mutf8Units(dex.strings()[i - 1U].mutf8) <
                    Mutf8Units(dex.strings()[i].mutf8);
            }
            auto ordered_fields = true;
            for (std::size_t i = 1; i < dex.fields().size(); ++i) ordered_fields &= std::tie(dex.fields()[i - 1U].class_idx, dex.fields()[i - 1U].name_idx, dex.fields()[i - 1U].type_idx) < std::tie(dex.fields()[i].class_idx, dex.fields()[i].name_idx, dex.fields()[i].type_idx);
            auto ordered_methods = true;
            for (std::size_t i = 1; i < dex.methods().size(); ++i) ordered_methods &= std::tie(dex.methods()[i - 1U].class_idx, dex.methods()[i - 1U].name_idx, dex.methods()[i - 1U].proto_idx) < std::tie(dex.methods()[i].class_idx, dex.methods()[i].name_idx, dex.methods()[i].proto_idx);
            std::cout << "string-order=" << (ordered_strings ? "ok" : "invalid") << " field-order=" << (ordered_fields ? "ok" : "invalid") << " method-order=" << (ordered_methods ? "ok" : "invalid") << '\n';
            const auto report = birch::dex::VerifyDex(
                dex, birch::dex::VerificationLevel::Full);
            std::cout << "full-verifier: " << (report.ok ? "ok" : "invalid")
                      << " (methods=" << report.methods
                      << ", code-items=" << report.code_items
                      << ", blocks=" << report.basic_blocks << ")\n";
            if (!report.ok) {
                for (const auto& issue : report.issues) {
                    std::cerr << "verify error at 0x" << std::hex
                              << issue.offset << std::dec << ": "
                              << issue.message << '\n';
                }
                return 1;
            }
        }
        if (command == DiagnosticCommand::ScanCfg) {
            std::size_t code_items = 0;
            std::size_t blocks = 0;
            for (std::size_t class_index = 0; class_index < dex.classes().size(); ++class_index) {
                const auto& data = dex.class_data(class_index);
                const auto scan = [&](const auto& methods) {
                    for (const auto& method : methods) {
                        if (method.code_off == 0U) {
                            continue;
                        }
                        const auto ir = birch::dex::BuildMethodIr(
                            birch::dex::DecodeCodeItem(dex, method.code_off));
                        const birch::dex::ControlFlowGraph cfg(ir);
                        if (!cfg.Verify()) {
                            throw std::runtime_error("internal CFG verification failed");
                        }
                        ++code_items;
                        blocks += ir.blocks().size();
                    }
                };
                scan(data.direct_methods);
                scan(data.virtual_methods);
            }
            std::cout << "code items: " << code_items << '\n'
                      << "basic blocks: " << blocks << '\n';
        }
        if (command == DiagnosticCommand::AuditCff) {
            return AuditCff(input);
        }
    } catch (const birch::dex::DexParseError& error) {
        std::cerr << "invalid DEX at offset 0x" << std::hex << error.offset()
                  << ": " << error.what() << '\n';
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "Birch: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
