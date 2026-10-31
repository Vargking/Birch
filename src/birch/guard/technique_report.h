#pragma once
#include "birch/guard/config.h"
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace birch::guard::detail {
class TechniqueReport final {
public:
    void Add(const std::map<std::string, std::size_t, std::less<>>& counters);
    void Count(std::string id, std::size_t count);
    static std::filesystem::path Path(const std::filesystem::path& output);
    static void ValidatePaths(const GuardConfig& config, const std::filesystem::path& input,
                              const std::filesystem::path& output);
    [[nodiscard]] std::string Render(const GuardConfig& config,
        const std::vector<std::string>& warnings, bool apk) const;
    void Write(const GuardConfig& config, const std::filesystem::path& output,
               const std::vector<std::string>& warnings, bool apk) const;
private:
    std::map<std::string, std::size_t, std::less<>> counters_;
};
}
