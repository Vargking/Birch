#pragma once

#include "birch/dex/program.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace birch::dex {

struct IdLimits {
    std::uint32_t strings{64000U};
    std::uint32_t types{64000U};
    std::uint32_t protos{64000U};
    std::uint32_t fields{64000U};
    std::uint32_t methods{64000U};
    std::uint32_t call_sites{64000U};
    std::uint32_t method_handles{64000U};

    void Validate() const;
};

struct ClassFootprint {
    std::set<std::string> strings;
    std::set<std::string> types;
    std::set<std::string> protos;
    std::set<std::string> fields;
    std::set<std::string> methods;
    std::set<std::string> call_sites;
    std::set<std::string> method_handles;
};

struct DexPartition {
    std::vector<ClassHandle> classes;
    ClassFootprint footprint;
};

struct PartitionOptions {
    IdLimits limits;
    std::set<std::string> primary_dex_classes;
    bool preserve_input_order{true};
};

void MergeClassFootprint(ClassFootprint& destination,
                         const ClassFootprint& source);
[[nodiscard]] bool ClassFootprintFits(const ClassFootprint& current,
                                      const ClassFootprint& addition,
                                      const IdLimits& limits);
ClassFootprint CollectClassFootprint(const DexProgram& program, ClassHandle handle);
std::vector<DexPartition> PartitionProgram(const DexProgram& program,
                                           const PartitionOptions& options);

} // namespace birch::dex
