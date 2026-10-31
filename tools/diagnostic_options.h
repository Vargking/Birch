#pragma once

#include <filesystem>
#include <iosfwd>
#include <span>
#include <string_view>

namespace birch::cli {

enum class DiagnosticCommand {
    Help, InspectDex, Map, Verify, ScanCfg, AuditCff, Partition, InspectApk,
};

// Argument validation is independent of DEX I/O: invalid invocations never
// read an input file or silently succeed after an unrecognized option.
class DiagnosticOptions {
public:
    static DiagnosticOptions Parse(std::span<const std::string_view> arguments);
    static void PrintUsage(std::ostream& output);

    [[nodiscard]] DiagnosticCommand command() const noexcept { return command_; }
    [[nodiscard]] const std::filesystem::path& input() const noexcept { return input_; }

private:
    DiagnosticOptions(DiagnosticCommand command, std::string_view input);
    DiagnosticCommand command_;
    std::filesystem::path input_;
};

} // namespace birch::cli
