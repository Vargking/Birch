#include "diagnostic_options.h"

#include <ostream>
#include <stdexcept>
#include <string>

namespace birch::cli {

DiagnosticOptions::DiagnosticOptions(DiagnosticCommand command, std::string_view input)
    : command_(command), input_(input) {}

DiagnosticOptions DiagnosticOptions::Parse(std::span<const std::string_view> arguments) {
    if (arguments.empty() || arguments.size() > 2U)
        throw std::invalid_argument("expected an input path and at most one option");
    const auto first = arguments.front();
    if (first == "--help" || first == "-h") {
        if (arguments.size() != 1U)
            throw std::invalid_argument("help does not accept additional arguments");
        return {DiagnosticCommand::Help, {}};
    }
    if (first == "--partition" || first == "--inspect-apk") {
        if (arguments.size() != 2U || arguments[1].empty() ||
            arguments[1].starts_with('-'))
            throw std::invalid_argument("expected an input path after " + std::string(first));
        return {first == "--partition" ? DiagnosticCommand::Partition :
                                        DiagnosticCommand::InspectApk, arguments[1]};
    }
    if (first.empty() || first.starts_with('-'))
        throw std::invalid_argument("unknown option: " + std::string(first));
    auto command = DiagnosticCommand::InspectDex;
    if (arguments.size() == 2U) {
        const auto option = arguments[1];
        if (option == "--map") command = DiagnosticCommand::Map;
        else if (option == "--verify") command = DiagnosticCommand::Verify;
        else if (option == "--scan-cfg") command = DiagnosticCommand::ScanCfg;
        else if (option == "--audit-cff") command = DiagnosticCommand::AuditCff;
        else throw std::invalid_argument("unknown DEX option: " + std::string(option));
    }
    return {command, first};
}

void DiagnosticOptions::PrintUsage(std::ostream& output) {
    output << "usage: Birch <classes.dex> [--map|--scan-cfg|--verify|--audit-cff]\n"
           << "       Birch --partition <dex-directory>\n"
           << "       Birch --inspect-apk <apk>\n"
           << "       Birch --help|-h\n";
}

} // namespace birch::cli
