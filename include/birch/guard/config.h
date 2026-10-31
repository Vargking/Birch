#pragma once

#include "birch/dex/partition.h"
#include "birch/guard/pass.h"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace birch::guard {

struct ScopeRule {
    std::string pattern;
    bool include_members{true};
    bool allow_renaming{true};
    bool allow_code_transforms{true};
};

struct ScopeConfig {
    std::vector<ScopeRule> protect;
    std::vector<ScopeRule> keep;
};

struct SafetyBudget {
    std::uint32_t max_code_units_per_method{60000U};
    std::uint32_t max_registers_per_method{240U};
    std::uint32_t max_added_blocks_per_method{128U};
    std::uint32_t max_added_try_regions_per_method{32U};
    double max_method_growth_ratio{4.0};
    double max_dex_growth_ratio{2.0};
    std::uint32_t max_analysis_blocks_per_method{4096U};
    std::uint32_t max_call_depth_increase{16U};
};

struct PassConfig {
    bool enabled{};
    double intensity{};
    std::optional<std::uint64_t> seed;
    std::optional<std::uint32_t> max_applications_per_method;
};

struct RenameConfig {
    std::string dictionary;
    std::string package_prefix{"b"};
    bool overload_methods{true};
    bool rename_source_files{true};
};

struct MultiDexConfig {
    dex::IdLimits limits;
    bool repartition{false};
    bool preserve_input_order{true};
    std::vector<std::string> primary_dex_classes;
};

struct StrengthConfig {
    bool per_method_strategy{true};
    bool randomized_parameters{true};
    bool reproducible_output{true};
    bool anti_automation_profile{true};
    std::uint32_t target_analysis_cost_weeks{0U};
};

struct FakeConfig {
    std::string package_prefix{"Lx/fake/"};
    std::uint32_t class_count{48U};
    std::uint32_t methods_per_class{8U};
};

struct ResourceConfig {
    bool rename_files{false};
    bool rename_names{false};
    std::string dictionary;
};

struct SigningConfig {
    bool enabled{false};
    std::string keystore;
    std::string alias;
};

struct OutputConfig {
    std::string mapping_file;
    bool write_mapping{true};
};

struct GuardConfig {
    std::uint32_t schema_version{1U};
    std::uint64_t seed{};
    // Replay a recorded effective seed without changing any pass or intensity.
    std::optional<std::uint64_t> effective_seed;
    // Optional Android framework DEX used to resolve superclass/interface
    // contracts while planning renames. It is metadata only and is never
    // copied into the output APK.
    std::string android_dex;
    ScopeConfig scope;
    SafetyBudget budget;
    RenameConfig rename;
    MultiDexConfig multidex;
    StrengthConfig strength;
    FakeConfig fake;
    ResourceConfig resources;
    SigningConfig signing;
    OutputConfig output;
    std::map<std::string, PassConfig, std::less<>> passes;

    static GuardConfig Defaults();
    static GuardConfig Parse(std::string_view json_source);
    void Validate() const;
};

std::string DefaultRenameDictionary();
[[nodiscard]] std::uint64_t StrengthRandomizedSeed(const GuardConfig& config);

} // namespace birch::guard
