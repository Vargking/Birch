#include "string_dex_interpreter.h"
#include "dex_integer_ops.h"
#include "dex_string_codec.h"
#include "dex_exception.h"

#include <bit>
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace birch::test {
using namespace integer;

std::uint32_t StringDexInterpreter::Run(
    const dex::CodeItem& code, std::span<const std::uint32_t> args, std::size_t depth, std::uint32_t method) {
    if (code.ins_size != args.size() || args.size() > code.registers_size)
        throw std::runtime_error("string oracle argument count mismatch");
    std::vector<std::uint32_t> regs(code.registers_size);
    std::vector<bool> initialized(code.registers_size);
    const auto read = [&](std::size_t r) {
        if (!initialized.at(r)) throw std::runtime_error("string oracle undefined v" + std::to_string(r));
        return regs.at(r);
    };
    const auto write = [&](std::size_t r, std::uint32_t value) {
        regs.at(r) = value;
        initialized.at(r) = true;
    };
    for (std::size_t i = 0; i < args.size(); ++i)
        write(regs.size() - args.size() + i, args[i]);
    const auto& decoded = decoded_.at(method);
    const auto word32 = [&](std::size_t at) {
        return std::uint32_t(code.insns.at(at)) | (std::uint32_t(code.insns.at(at + 1U)) << 16U);
    };
    std::optional<std::uint32_t> result;
    std::optional<std::uint32_t> exception;
    // Single-threaded structured-monitor oracle, not a scheduler/ART model.
    // Keep identities frame-local so moving a lock boundary into a helper
    // cannot accidentally pass as a no-op.
    std::vector<std::uint32_t> monitors;
    const auto finish = [&](std::uint32_t value) {
        if (!monitors.empty()) throw std::runtime_error("string oracle return with held monitor");
        return value;
    };
    std::uint32_t pc = 0;
    std::size_t local_steps = 0;
    std::vector<std::size_t> visits(code.insns.size());
    while (++steps_ < max_steps_) {
        ++local_steps;
        if (local_steps > 1000000U)
            throw std::runtime_error("string oracle per-frame instruction budget exceeded at " + std::to_string(pc));
        ++method_steps_[method];
        ++visits.at(pc);
        const auto* ins = decoded.at(pc);
        if (!ins) throw std::runtime_error("string oracle jump into payload/interior");
        const auto op = ins->opcode;
        const auto a = code.insns.at(pc) >> 8U;
        const auto unit = [&] { return code.insns.at(pc + 1U); };
        auto next = pc + ins->width;
        try {
        if (op == 0x00U) { }
        else if (op == 0x01U || op == 0x07U) write(a & 15U, read(a >> 4U));
        else if (op == 0x02U || op == 0x08U) write(a, read(unit()));
        else if (op == 0x03U || op == 0x09U) write(unit(), read(code.insns.at(pc + 2U)));
        else if (op == 0x0aU || op == 0x0cU) {
            if (!result) throw std::runtime_error("string oracle missing invoke result");
            write(a, *result);
            result.reset();
        } else if (op == 0x0dU) {
            if (!exception) throw std::runtime_error("move-exception without a pending exception");
            write(a, *exception);
            exception.reset();
        } else if (op == 0x0eU) return finish(0U);
        else if (op == 0x0fU || op == 0x11U) return finish(read(a));
        else if (op == 0x12U) {
            auto value = static_cast<std::uint8_t>(a >> 4U);
            write(a & 15U, Sign8(value < 8U ? value : value | 0xf0U));
        } else if (op == 0x13U) write(a, Sign16(unit()));
        else if (op == 0x14U) write(a, word32(pc + 1U));
        else if (op == 0x15U) write(a, std::uint32_t(unit()) << 16U);
        else if (op == 0x1aU || op == 0x1bU)
            write(a, Intern(Allocate({"Ljava/lang/String;", {}, Utf16(file_.string(op == 0x1aU ? unit() : word32(pc + 1U)))})));
        else if (op == 0x1cU) {
            const auto type = file_.descriptor(unit());
            if (!class_objects_.contains(type))
                class_objects_[type] = Allocate({"Ljava/lang/Class;", {}, {}});
            write(a, class_objects_.at(type));
        } else if (op == 0x1dU || op == 0x1eU) {
            const auto identity = read(a);
            (void)Heap(identity); // null/invalid monitor is not silently accepted
            if (op == 0x1dU) monitors.push_back(identity);
            else {
                if (monitors.empty() || monitors.back() != identity)
                    throw std::runtime_error("string oracle mismatched monitor-exit");
                monitors.pop_back();
            }
        } else if (op == 0x1fU) { // check-cast permits null without dereferencing it
            const auto object = read(a);
            if (object != 0U) (void)Heap(object);
        }
        else if (op == 0x21U) write(a & 15U, static_cast<std::uint32_t>(Heap(read(a >> 4U)).elements.size()));
        else if (op == 0x22U) write(a, Allocate({file_.descriptor(unit()), {}, {}}));
        else if (op == 0x23U) {
            const auto count = read(a >> 4U);
            if (count > 1000000U) throw std::runtime_error("string oracle invalid array size");
            write(a & 15U, Allocate({file_.descriptor(unit()), std::vector<std::uint32_t>(count), {}}));
        } else if (op == 0x26U) {
            const auto payload = pc + word32(pc + 1U);
            if (code.insns.at(payload) != 0x0300U) throw std::runtime_error("invalid array payload");
            const auto width = code.insns.at(payload + 1U);
            const auto count = word32(payload + 2U);
            auto& array = Heap(read(a));
            if (count > array.elements.size() || (width != 1U && width != 2U && width != 4U))
                throw std::runtime_error("invalid array payload dimensions");
            for (std::size_t i = 0; i < count; ++i) {
                std::uint32_t value = 0;
                for (unsigned b = 0; b < width; ++b) {
                    const auto offset = i * width + b;
                    value |= ((code.insns.at(payload + 4U + offset / 2U) >> ((offset % 2U) * 8U)) & 255U) << (b * 8U);
                }
                array.elements.at(i) = value;
            }
        } else if (op == 0x27U) {
            auto thrown = read(a);
            if (thrown == 0U) thrown = Allocate({"Ljava/lang/NullPointerException;", {}, {}});
            (void)Heap(thrown);
            throw DexThrown{thrown};
        } else if (op == 0x28U) next = pc + Sign8(static_cast<std::uint8_t>(a));
        else if (op == 0x29U) next = pc + Sign16(unit());
        else if (op == 0x2aU) next = pc + word32(pc + 1U);
        else if (op == 0x2bU || op == 0x2cU) {
            const auto payload = pc + word32(pc + 1U);
            if (code.insns.at(payload) != (op == 0x2bU ? 0x0100U : 0x0200U))
                throw std::runtime_error("invalid switch payload");
            const auto count = code.insns.at(payload + 1U);
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto key = op == 0x2bU ? word32(payload + 2U) + i : word32(payload + 2U + i * 2U);
                if (read(a) != key) continue;
                const auto targets = payload + (op == 0x2bU ? 4U : 2U + count * 2U);
                next = pc + word32(targets + i * 2U);
                break;
            }
        } else if (op == 0x2dU || op == 0x2eU) {
            const auto left = std::bit_cast<float>(read(unit() & 255U));
            const auto right = std::bit_cast<float>(read(unit() >> 8U));
            const auto comparison = (std::isnan(left) || std::isnan(right)) ?
                (op == 0x2dU ? -1 : 1) : left < right ? -1 : left > right ? 1 : 0;
            write(a, static_cast<std::uint32_t>(comparison));
        } else if (op >= 0x32U && op <= 0x37U) {
            if (Compare(op - 0x32U, read(a & 15U), read(a >> 4U))) next = pc + Sign16(unit());
        } else if (op >= 0x38U && op <= 0x3dU) {
            if (Compare(op - 0x38U, read(a), 0)) next = pc + Sign16(unit());
        } else if (op == 0x44U || (op >= 0x47U && op <= 0x4aU)) {
            const auto value = Heap(read(unit() & 255U)).elements.at(read(unit() >> 8U));
            write(a, op == 0x48U ? Sign8(static_cast<std::uint8_t>(value)) :
                op == 0x4aU ? Sign16(static_cast<std::uint16_t>(value)) : value);
        } else if (op == 0x4bU || (op >= 0x4eU && op <= 0x51U)) {
            const auto value = read(a);
            Heap(read(unit() & 255U)).elements.at(read(unit() >> 8U)) =
                op == 0x4fU ? value & 255U : (op == 0x50U || op == 0x51U) ? value & 65535U : value;
        } else if ((op >= 0x60U && op <= 0x66U) || (op >= 0x67U && op <= 0x6dU)) {
            const auto field = unit();
            Initialize(file_.descriptor(file_.fields().at(field).class_idx), depth);
            if (op <= 0x66U) write(a, fields_.at(field));
            else fields_.at(field) = read(a);
        } else if ((op >= 0x6eU && op <= 0x72U) || (op >= 0x74U && op <= 0x78U)) {
            std::vector<std::uint32_t> values;
            const auto last = code.insns.at(pc + 2U);
            if (op >= 0x74U) {
                for (unsigned i = 0; i < a; ++i) values.push_back(read(last + i));
            } else {
                const std::uint16_t registers[]{std::uint16_t(last & 15U), std::uint16_t((last >> 4U) & 15U),
                    std::uint16_t((last >> 8U) & 15U), std::uint16_t(last >> 12U), std::uint16_t(a & 15U)};
                if ((a >> 4U) > 5U) throw std::runtime_error("invalid invoke count");
                for (unsigned i = 0; i < (a >> 4U); ++i) values.push_back(read(registers[i]));
            }
            result = Call(unit(), values, depth + 1U);
        } else if (op == 0x7bU) write(a & 15U, 0U - read(a >> 4U));
        else if (op == 0x7cU) write(a & 15U, ~read(a >> 4U));
        else if (op == 0x8dU) write(a & 15U, Sign8(static_cast<std::uint8_t>(read(a >> 4U))));
        else if (op == 0x8eU) write(a & 15U, read(a >> 4U) & 65535U);
        else if (op == 0x8fU) write(a & 15U, Sign16(static_cast<std::uint16_t>(read(a >> 4U))));
        else if (op >= 0x90U && op <= 0x9aU) write(a, Arithmetic(op - 0x90U, read(unit() & 255U), read(unit() >> 8U)));
        else if (op >= 0xb0U && op <= 0xbaU) write(a & 15U, Arithmetic(op - 0xb0U, read(a & 15U), read(a >> 4U)));
        else if (op >= 0xd0U && op <= 0xd7U) {
            const auto left = read(a >> 4U), right = Sign16(unit());
            write(a & 15U, op == 0xd1U ? right - left : Arithmetic(op - 0xd0U, left, right));
        } else if (op >= 0xd8U && op <= 0xe2U) {
            const auto left = read(unit() & 255U), right = Sign8(static_cast<std::uint8_t>(unit() >> 8U));
            write(a, op == 0xd9U ? right - left : Arithmetic(op - 0xd8U, left, right));
        } else throw std::runtime_error("string oracle unsupported opcode " + std::to_string(op) + " at " + std::to_string(pc));
        } catch (const DexThrown& thrown) {
            bool handled = false;
            const auto& type = Heap(thrown.object).type;
            for (const auto& region : code.tries) {
                if (pc < region.start_address || pc - region.start_address >= region.instruction_count) continue;
                for (const auto& handler : region.handlers) {
                    if (handler.type_idx && !MatchesException(file_.descriptor(*handler.type_idx), type)) continue;
                    exception = thrown.object;
                    result.reset();
                    next = handler.address;
                    handled = true;
                    break;
                }
                if (handled) break;
            }
            if (!handled) {
                if (!monitors.empty()) throw std::runtime_error("string oracle exception escapes with held monitor");
                throw; // An invoke's DEX exception must reach the caller's try.
            }
        }
        pc = next;
    }
    std::string detail = "string oracle instruction budget exceeded at pc=" + std::to_string(pc) +
        " frame_steps=" + std::to_string(local_steps) + " visits=" + std::to_string(visits.at(pc));
    for (std::size_t i = 0; i < regs.size(); ++i)
        if (initialized[i]) detail += " v" + std::to_string(i) + "=" + std::to_string(regs[i]);
    std::vector<std::pair<std::size_t, std::uint32_t>> hottest;
    for (const auto& [index, count] : method_steps_) hottest.emplace_back(count, index);
    std::sort(hottest.rbegin(), hottest.rend());
    for (std::size_t i = 0; i < std::min<std::size_t>(hottest.size(), 10U); ++i) {
        const auto [count, index] = hottest[i];
        const auto& id = file_.methods().at(index);
        detail += "\n" + file_.descriptor(id.class_idx) + "->" + file_.string(id.name_idx) +
            " steps=" + std::to_string(count) + " calls=" + std::to_string(calls_[index]);
    }
    throw std::runtime_error(detail);
}

} // namespace birch::test
