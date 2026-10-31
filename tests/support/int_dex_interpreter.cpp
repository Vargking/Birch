#include "int_dex_interpreter.h"
#include "dex_integer_ops.h"

#include <bit>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace birch::test {
using namespace integer;

std::uint32_t IntDexInterpreter::Execute(
    const dex::CodeItem& code, std::span<const std::uint32_t> arguments) {
    if (code.ins_size != arguments.size() || code.ins_size > code.registers_size)
        throw std::runtime_error("integer oracle argument count mismatch");
    std::vector<std::uint32_t> regs(code.registers_size);
    std::vector<bool> initialized(code.registers_size);
    const auto read = [&](std::size_t reg) {
        if (!initialized.at(reg)) throw std::runtime_error("oracle uninitialized register");
        return regs.at(reg);
    };
    const auto write = [&](std::size_t reg, std::uint32_t value) {
        regs.at(reg) = value;
        initialized.at(reg) = true;
    };
    for (std::size_t i = 0; i < arguments.size(); ++i)
        write(code.registers_size - arguments.size() + i, arguments[i]);
    std::vector<const dex::DecodedInstruction*> decoded(code.insns.size());
    for (const auto& instruction : code.instructions)
        if (instruction.kind != dex::InstructionKind::Payload)
            decoded.at(instruction.offset) = &instruction;
    const auto word32 = [&](std::size_t at) {
        return static_cast<std::uint32_t>(code.insns.at(at)) |
               (static_cast<std::uint32_t>(code.insns.at(at + 1U)) << 16U);
    };
    std::uint32_t pc = 0;
    for (std::size_t steps = 0; steps < 1000000U; ++steps) {
        const auto* instruction = decoded.at(pc);
        if (instruction == nullptr) throw std::runtime_error("oracle jump into payload/interior");
        const auto first = code.insns.at(pc);
        const auto op = instruction->opcode;
        const auto a = first >> 8U;
        auto next = pc + instruction->width;
        const auto unit = [&] { return code.insns.at(pc + 1U); };
        const auto jump16 = [&] { return pc + Sign16(unit()); };
        if (op == 0x00U) { /* nop */ }
        else if (op == 0x01U) write(a & 15U, read(a >> 4U));
        else if (op == 0x02U) write(a, read(unit()));
        else if (op == 0x03U) write(unit(), read(code.insns.at(pc + 2U)));
        else if (op == 0x0fU) return read(a);
        else if (op == 0x12U) {
            const auto literal = static_cast<std::uint8_t>(a >> 4U);
            write(a & 15U, Sign8(static_cast<std::uint8_t>(
                literal < 8U ? literal : literal | 0xf0U)));
        } else if (op == 0x13U) write(a, Sign16(unit()));
        else if (op == 0x14U) write(a, word32(pc + 1U));
        else if (op == 0x15U) write(a, static_cast<std::uint32_t>(unit()) << 16U);
        else if (op == 0x28U) next = pc + Sign8(static_cast<std::uint8_t>(a));
        else if (op == 0x29U) next = jump16();
        else if (op == 0x2aU) next = pc + word32(pc + 1U);
        else if (op == 0x2bU || op == 0x2cU) {
            const auto payload = pc + word32(pc + 1U);
            const auto expected = op == 0x2bU ? 0x0100U : 0x0200U;
            if (code.insns.at(payload) != expected)
                throw std::runtime_error("oracle wrong switch payload");
            const auto count = code.insns.at(payload + 1U);
            const auto value = read(a);
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto key = op == 0x2bU ? word32(payload + 2U) + i :
                    word32(payload + 2U + i * 2U);
                if (value != key) continue;
                const auto targets = payload + (op == 0x2bU ? 4U : 2U + count * 2U);
                next = pc + word32(targets + i * 2U);
                break;
            }
        } else if (op >= 0x32U && op <= 0x37U) {
            if (Compare(op - 0x32U, read(a & 15U), read(a >> 4U))) next = jump16();
        } else if (op >= 0x38U && op <= 0x3dU) {
            if (Compare(op - 0x38U, read(a), 0U)) next = jump16();
        } else if (op == 0x7bU) write(a & 15U, 0U - read(a >> 4U));
        else if (op == 0x7cU) write(a & 15U, ~read(a >> 4U));
        else if (op >= 0x90U && op <= 0x9aU)
            write(a, Arithmetic(op - 0x90U, read(unit() & 255U), read(unit() >> 8U)));
        else if (op >= 0xb0U && op <= 0xbaU)
            write(a & 15U, Arithmetic(op - 0xb0U, read(a & 15U), read(a >> 4U)));
        else if (op >= 0xd0U && op <= 0xd7U) {
            const auto left = read(a >> 4U), right = Sign16(unit());
            write(a & 15U, op == 0xd1U ? right - left :
                Arithmetic(op - 0xd0U, left, right));
        } else if (op >= 0xd8U && op <= 0xe2U) {
            const auto left = read(unit() & 255U);
            const auto right = Sign8(static_cast<std::uint8_t>(unit() >> 8U));
            write(a, op == 0xd9U ? right - left : Arithmetic(op - 0xd8U, left, right));
        } else throw std::runtime_error("integer oracle unsupported opcode: " + std::to_string(op));
        pc = next;
    }
    throw std::runtime_error("integer oracle instruction budget exceeded");
}

} // namespace birch::test
