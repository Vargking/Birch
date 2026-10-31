#pragma once

#include "birch/dex/dex_file.h"
#include "birch/guard/config.h"
#include "birch/guard/model_lowering.h"

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace birch::guard::detail {

struct DexRenameResult {
    std::vector<std::uint8_t> bytes;
    std::size_t classes{};
    std::size_t methods{};
    std::size_t fields{};
    std::map<std::string, std::string, std::less<>> class_map;
    std::vector<std::string> mapping_lines;
    std::vector<std::string> warnings;
};

struct GlobalRenamePlan {
    std::map<std::string, std::string, std::less<>> classes;
    std::map<std::string, std::string, std::less<>> methods;
    std::map<std::string, std::string, std::less<>> fields;
    std::vector<std::string> warnings;
};

// One global rename closure shared by every DEX and reflection site.
class RenamePlanner final {
public:
    static ReflectionRenamePlan BuildReflectionRenamePlan(
        const GlobalRenamePlan& rename_plan);

    static void MergeReflectionRenamePlan(ReflectionRenamePlan& destination,
                                   const ReflectionRenamePlan& source);

    static bool EmptyReflectionRenamePlan(const ReflectionRenamePlan& plan);

    static GlobalRenamePlan BuildReflectionRenameLocks(
        const ReflectionRenamePlan& plan);

    static void ValidateStablePreModelRenamePlan(
        const GlobalRenamePlan& before_model,
        const GlobalRenamePlan& final_plan);

    static GlobalRenamePlan BuildGlobalRenamePlan(
        const std::vector<std::reference_wrapper<const dex::DexFile>>& dex_files,
        const ScopeConfig& scope, const RenameConfig& rename, std::uint64_t seed,
        bool rename_classes, bool rename_methods, bool rename_fields,
        bool overload_induction, double overload_intensity,
        const dex::DexFile* framework_dex = nullptr,
        const GlobalRenamePlan* locked_plan = nullptr);

    static DexRenameResult RenameDex(const dex::DexFile& dex, const ScopeConfig& scope,
                              const RenameConfig& rename, std::uint64_t seed,
                              bool rename_classes, bool rename_methods, bool rename_fields,
                              const GlobalRenamePlan* global_plan = nullptr);
};

} // namespace birch::guard::detail

