#pragma once

#include "birch/dex/dex_file.h"

#include <cstddef>
#include <string>
#include <vector>

namespace birch::dex {

enum class VerificationLevel {
    Structural,
    Code,
    Full,
};

struct VerificationIssue {
    DexErrorCode code{DexErrorCode::InvalidHeader};
    std::size_t offset{};
    std::string message;
};

struct VerificationReport {
    bool ok{};
    std::size_t classes{};
    std::size_t methods{};
    std::size_t code_items{};
    std::size_t basic_blocks{};
    std::vector<VerificationIssue> issues;
};

VerificationReport VerifyDex(const DexFile& dex,
                             VerificationLevel level = VerificationLevel::Full);
void VerifyDexOrThrow(const DexFile& dex,
                      VerificationLevel level = VerificationLevel::Full);

} // namespace birch::dex
