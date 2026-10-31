#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <vector>

namespace birch::guard::detail {

class CffAssembler final {
  public:
    using Label = std::size_t;

    // Only use when the accepted method-size ceiling is below INT16_MAX.
    void UseCompactBranches() noexcept { compact_branches_ = true; }
    [[nodiscard]] Label NewLabel();
    void Bind(Label label);
    void Emit(std::span<const std::uint16_t> units);
    void Emit(std::initializer_list<std::uint16_t> units);
    void EmitConst32(std::uint16_t reg, std::uint32_t value);
    void EmitXor(std::uint16_t destination, std::uint16_t left, std::uint16_t right);
    void AlignPayload(std::uint16_t scratch_register);
    [[nodiscard]] static std::size_t AlignedPayloadPosition(std::size_t position, std::uint16_t scratch_register);
    void EmitEncodedState(std::uint16_t reg, std::uint32_t value, std::uint64_t salt);
    void EmitRuntimeEncodedState(std::uint16_t reg, std::uint32_t value, std::uint64_t salt,
                                 std::optional<std::uint16_t> barrier_method);
    [[nodiscard]] bool EmitRelativeEncodedState(std::uint16_t reg, std::uint32_t current,
                                                std::uint32_t target, std::uint64_t salt);
    void EmitGoto32(Label target);
    void EmitGoto16(Label target);
    void EmitGoto8(Label target);
    void EmitIf16(std::uint16_t first, Label target);
    [[nodiscard]] std::size_t position() const noexcept;
    [[nodiscard]] const std::optional<std::size_t> &LabelPosition(Label label) const;
    [[nodiscard]] bool HasBranchTo(Label label) const;
    std::vector<std::uint16_t> Finish() &&;

  private:
    enum class FixupKind : std::uint8_t { Branch8, Branch16, Branch32 };
    struct Fixup {
        std::size_t at{};
        Label label{};
        FixupKind kind{};
    };
    std::vector<std::uint16_t> code_;
    std::vector<std::optional<std::size_t>> labels_;
    std::vector<Fixup> fixups_;
    bool compact_branches_{};
};

std::uint16_t InverseIfOpcode(std::uint8_t opcode);

} // namespace birch::guard::detail
