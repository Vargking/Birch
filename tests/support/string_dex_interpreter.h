#pragma once

#include "birch/dex/code.h"

#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace birch::test {

// Independent, strict DEX execution oracle for the string protection surface.
// Not an ART replacement: unsupported framework calls/opcodes fail the test.
class StringDexInterpreter final {
public:
    explicit StringDexInterpreter(const dex::DexFile& file, std::size_t max_steps = 20000000U);
    std::u16string Execute(std::string_view owner, std::string_view name);
    std::uint32_t ExecuteScalar(std::string_view owner, std::string_view name,
        std::span<const std::uint32_t> arguments = {}, std::string_view prototype = "()I");
    bool HasStableIdentity(std::string_view owner, std::string_view name);
    [[nodiscard]] std::size_t ExecutedInstructions() const noexcept { return steps_; }

private:
    struct Object {
        std::string type;
        std::vector<std::uint32_t> elements;
        std::u16string text;
    };
    std::uint32_t Allocate(Object object);
    std::uint32_t Intern(std::uint32_t handle);
    std::uint32_t Entry(std::string_view owner, std::string_view name,
                        std::string_view prototype = "()Ljava/lang/String;",
                        std::span<const std::uint32_t> arguments = {});
    Object& Heap(std::uint32_t handle);
    std::uint32_t Call(std::uint32_t method, std::span<const std::uint32_t> args,
                       std::size_t depth);
    void Initialize(std::string_view owner, std::size_t depth);
    std::uint32_t Run(const dex::CodeItem& code,
                      std::span<const std::uint32_t> args, std::size_t depth, std::uint32_t method);

    const dex::DexFile& file_;
    std::map<std::uint32_t, dex::CodeItem> methods_;
    std::map<std::uint32_t, std::vector<const dex::DecodedInstruction*>> decoded_;
    std::map<std::uint32_t, std::uint32_t> fields_;
    std::map<std::string, unsigned, std::less<>> initialized_;
    std::map<std::string, std::uint32_t, std::less<>> class_objects_;
    std::map<std::u16string, std::uint32_t> interned_;
    std::optional<std::uint32_t> class_loader_;
    std::vector<Object> heap_;
    std::size_t steps_{};
    std::size_t max_steps_;
    std::map<std::uint32_t, std::size_t> calls_;
    std::map<std::uint32_t, std::size_t> method_steps_;
};

} // namespace birch::test
