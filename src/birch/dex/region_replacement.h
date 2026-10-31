#pragma once

#include "birch/dex/code.h"
#include "birch/dex/remap.h"

#include <set>

namespace birch::dex::detail {
// Recheck the structural proof at the writer boundary, then mark interior
// instructions as erased. Type/value proofs belong to the producing pass.
[[nodiscard]] std::set<std::uint32_t> PrepareOutlineReplacements(
    const CodeItem& code, CodePrefix& prefix);
}
