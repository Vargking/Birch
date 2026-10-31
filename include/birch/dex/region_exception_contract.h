#pragma once

#include "birch/dex/code.h"

#include <optional>

namespace birch::dex {

// An outlined call must inherit exactly the moved instructions' catch context.
// Register visibility on exceptional exits is a separate liveness proof.
class RegionExceptionContract final {
public:
    [[nodiscard]] static std::optional<RegionExceptionContract> Prove(
        const CodeItem& code, std::uint32_t start, std::uint32_t end);
    [[nodiscard]] const std::vector<std::uint32_t>& handlers() const noexcept {
        return handlers_;
    }
    [[nodiscard]] bool catches_all() const noexcept { return catches_all_; }

private:
    std::vector<std::uint32_t> handlers_;
    bool catches_all_{};
};

} // namespace birch::dex
