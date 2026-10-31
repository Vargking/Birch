#include "birch/dex/verifier.h"

#include "birch/dex/cfg.h"
#include "birch/dex/code.h"
#include "birch/dex/ir.h"
#include "birch/dex/type_analysis.h"

#include <algorithm>
#include <map>
#include <queue>
#include <string>

namespace birch::dex {
namespace {

void VerifyReachableFallthrough(const CodeItem& code) {
    std::map<std::uint32_t, const DecodedInstruction*> executable;
    for (const auto& instruction : code.instructions)
        if (instruction.kind != InstructionKind::Payload)
            executable.emplace(instruction.offset, &instruction);
    if (!executable.contains(0U)) throw std::runtime_error("method entry is not executable");
    std::vector<bool> visited(code.insns.size());
    std::queue<std::uint32_t> pending;
    const auto enqueue = [&](std::uint32_t target) {
        if (!executable.contains(target))
            throw std::runtime_error("reachable flow falls off code or into payload");
        if (!visited.at(target)) {
            visited[target] = true;
            pending.push(target);
        }
    };
    enqueue(0U);
    while (!pending.empty()) {
        const auto* instruction = executable.at(pending.front());
        pending.pop();
        for (const auto target : instruction->targets) enqueue(target);
        if (instruction->kind != InstructionKind::Return &&
            instruction->kind != InstructionKind::Throw &&
            instruction->kind != InstructionKind::UnconditionalBranch)
            enqueue(instruction->offset + instruction->width);
        if (instruction->can_throw)
            for (const auto& region : code.tries)
                if (instruction->offset >= region.start_address &&
                    instruction->offset - region.start_address < region.instruction_count)
                    for (const auto& handler : region.handlers) enqueue(handler.address);
    }
}

} // namespace

VerificationReport VerifyDex(const DexFile& dex, VerificationLevel level) {
    VerificationReport report;
    report.ok = true;
    report.classes = dex.classes().size();
    for (std::size_t class_index = 0; class_index < dex.classes().size(); ++class_index) {
        const auto& data = dex.class_data(class_index);
        const auto check_fields = [&](const auto& fields, bool expect_static) {
            constexpr std::uint32_t kStatic = 0x0008U;
            constexpr std::uint32_t kFinal = 0x0010U;
            constexpr std::uint32_t kVolatile = 0x0040U;
            for (const auto& field : fields) {
                const auto flags = field.access_flags;
                if ((flags & (kFinal | kVolatile)) ==
                    (kFinal | kVolatile)) {
                    report.ok = false;
                    report.issues.push_back({
                        DexErrorCode::InvalidClassData, 0U,
                        "field access flags combine final and volatile: " +
                            dex.field_key(field.field_idx)});
                }
                if (((flags & kStatic) != 0U) != expect_static) {
                    report.ok = false;
                    report.issues.push_back({
                        DexErrorCode::InvalidClassData, 0U,
                        std::string(expect_static ?
                            "static field is missing ACC_STATIC: " :
                            "instance field has ACC_STATIC: ") +
                            dex.field_key(field.field_idx)});
                }
            }
        };
        check_fields(data.static_fields, true);
        check_fields(data.instance_fields, false);
        const auto check_methods = [&](const auto& methods) {
            for (const auto& method : methods) {
                ++report.methods;
                if (method.code_off == 0U) continue;
                ++report.code_items;
                try {
                    const auto code = DecodeCodeItem(dex, method.code_off);
                    if (level == VerificationLevel::Structural) continue;
                    VerifyReachableFallthrough(code);
                    const auto ir = BuildMethodIr(code);
                    const ControlFlowGraph cfg(ir);
                    if (!cfg.Verify()) throw std::runtime_error("CFG verification failed");
                    report.basic_blocks += ir.blocks().size();
                    if (level == VerificationLevel::Full) {
                        const auto types = AnalyzeMethodTypes(dex, method, code);
                        for (const auto& issue : types.issues) {
                            report.ok = false;
                            report.issues.push_back({
                                DexErrorCode::InvalidClassData,
                                static_cast<std::size_t>(method.code_off) +
                                    16U + issue.instruction_offset * 2U,
                                dex.method_key(method.method_idx) + " [0x" +
                                    [&]() {
                                        constexpr char digits[] =
                                            "0123456789abcdef";
                                        auto value = issue.instruction_offset;
                                        std::string hex;
                                        do {
                                            hex.push_back(digits[value & 0x0fU]);
                                            value >>= 4U;
                                        } while (value != 0U);
                                        std::reverse(hex.begin(), hex.end());
                                        return hex;
                                    }() + "]: " + issue.message});
                        }
                    }
                } catch (const DexParseError& error) {
                    report.ok = false;
                    report.issues.push_back({error.code(), error.offset(), error.what()});
                } catch (const std::exception& error) {
                    report.ok = false;
                    report.issues.push_back({DexErrorCode::InvalidClassData, method.code_off, error.what()});
                }
            }
        };
        check_methods(data.direct_methods);
        check_methods(data.virtual_methods);
    }
    if (!dex.VerifyChecksums()) {
        report.ok = false;
        report.issues.push_back({DexErrorCode::InvalidHeader, 0x08U, "DEX checksum/signature mismatch"});
    }
    if (level == VerificationLevel::Full) {
        std::string issue;
        if (!dex.VerifyCanonicalOrder(&issue)) {
            report.ok = false;
            report.issues.push_back({DexErrorCode::InvalidIndex, 0U,
                                     "non-canonical DEX ID/class order: " + issue});
        }
    }
    return report;
}

void VerifyDexOrThrow(const DexFile& dex, VerificationLevel level) {
    const auto report = VerifyDex(dex, level);
    if (report.ok) return;
    throw std::runtime_error(report.issues.empty() ?
        "DEX verification failed" : report.issues.front().message);
}

} // namespace birch::dex
