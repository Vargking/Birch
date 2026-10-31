#include "birch/dex/type_analysis.h"

#include <algorithm>
#include <array>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace birch::dex {
namespace {

enum class ValueKind : std::uint8_t {
    Undefined,
    Unknown,
    Conflict,
    Scalar32,
    Int32,
    Float32,
    Reference,
    Scalar64Low,
    Scalar64High,
    LongLow,
    LongHigh,
    DoubleLow,
    DoubleHigh,
};

std::string_view ValueKindName(ValueKind kind) {
    switch (kind) {
        case ValueKind::Undefined: return "undefined";
        case ValueKind::Unknown: return "unknown";
        case ValueKind::Conflict: return "conflict";
        case ValueKind::Scalar32: return "scalar32";
        case ValueKind::Int32: return "int32";
        case ValueKind::Float32: return "float32";
        case ValueKind::Reference: return "reference";
        case ValueKind::Scalar64Low: return "scalar64-low";
        case ValueKind::Scalar64High: return "scalar64-high";
        case ValueKind::LongLow: return "long-low";
        case ValueKind::LongHigh: return "long-high";
        case ValueKind::DoubleLow: return "double-low";
        case ValueKind::DoubleHigh: return "double-high";
    }
    return "invalid";
}

struct RegisterValue {
    ValueKind kind{ValueKind::Undefined};
    std::string descriptor;
    std::vector<std::uint32_t> origins;
    bool all_zero{};
    // Allocation-site identity survives move-object until invoke-direct <init>.
    // UINT32_MAX denotes constructor-this; UINT32_MAX-1 is an ambiguous join.
    std::uint32_t uninitialized_id{};

    bool operator==(const RegisterValue&) const = default;
};

using RegisterState = std::vector<RegisterValue>;

enum class ExpectedType : std::uint8_t {
    Int32,
    Float32,
    Reference,
    Long,
    Double,
};

bool IsReferenceDescriptor(std::string_view descriptor) {
    return !descriptor.empty() &&
           (descriptor.front() == 'L' || descriptor.front() == '[');
}

class MethodAnalyzer final {
public:
    MethodAnalyzer(const DexFile& dex, const DexEncodedMethod& encoded,
                   const CodeItem& code, MethodTypeAnalysisOptions options)
        : dex_(dex), encoded_(encoded), code_(code),
          method_(dex.methods().at(encoded.method_idx)), options_(options),
          capture_exit_offsets_(options.capture_exit_offsets.begin(),
                                options.capture_exit_offsets.end()) {
        for (const auto& instruction : code_.instructions) {
            if (instruction.kind == InstructionKind::Payload) continue;
            index_by_offset_.emplace(instruction.offset, instructions_.size());
            instructions_.push_back(&instruction);
            if (IsConst32(instruction.opcode)) {
                result_.constant_uses.try_emplace(
                    instruction.offset, ConstantUseType::Unconstrained);
                if (Literal32(instruction) == 0U) {
                    zero_constants_.insert(instruction.offset);
                }
            }
        }
        for (const auto& region : code_.tries) {
            leaders_.insert(region.start_address);
            leaders_.insert(region.start_address + region.instruction_count);
            for (const auto& handler : region.handlers) {
                handler_offsets_.insert(handler.address);
                leaders_.insert(handler.address);
            }
        }
        if (!instructions_.empty()) leaders_.insert(instructions_.front()->offset);
        for (const auto* instruction : instructions_) {
            leaders_.insert(instruction->targets.begin(),
                            instruction->targets.end());
            if (instruction->kind == InstructionKind::ConditionalBranch ||
                instruction->kind == InstructionKind::UnconditionalBranch ||
                instruction->kind == InstructionKind::Switch ||
                instruction->kind == InstructionKind::Return ||
                instruction->kind == InstructionKind::Throw) {
                const auto next = instruction->offset + instruction->width;
                if (index_by_offset_.contains(next)) leaders_.insert(next);
            }
        }
    }

    MethodTypeAnalysis Run() {
        if (instructions_.empty()) return std::move(result_);
        std::vector<std::optional<RegisterState>> entries(instructions_.size());
        entries.front() = EntryState();
        std::deque<std::size_t> worklist{0U};
        std::vector<bool> queued(instructions_.size(), false);
        std::vector<bool> analyzed(instructions_.size(), false);
        queued.front() = true;

        for (;;) {
            while (!worklist.empty()) {
                const auto index = worklist.front();
                worklist.pop_front();
                queued[index] = false;
                if (!entries[index].has_value()) continue;
                const auto enqueue = [&](std::uint32_t target,
                                         const RegisterState& state,
                                         std::uint32_t source_offset) {
                    const auto found = index_by_offset_.find(target);
                    if (found == index_by_offset_.end()) return;
                    const auto target_index = found->second;
                    if (!entries[target_index].has_value()) {
                        entries[target_index] = state;
                        if (!queued[target_index]) {
                            queued[target_index] = true;
                            worklist.push_back(target_index);
                        }
                        return;
                    }
                    auto merged = *entries[target_index];
                    if (!MergeState(merged, state, source_offset)) return;
                    entries[target_index] = std::move(merged);
                    if (!queued[target_index]) {
                        queued[target_index] = true;
                        worklist.push_back(target_index);
                    }
                };

                auto state = *entries[index];
                for (auto cursor = index; cursor < instructions_.size(); ++cursor) {
                    analyzed[cursor] = true;
                    const auto before = state;
                    Transfer(cursor, state);
                    const auto& instruction = *instructions_[cursor];
                    if (capture_exit_offsets_.contains(instruction.offset)) {
                        if (options_.capture_type_snapshots) {
                            result_.entry_register_types[instruction.offset] = Snapshot(before);
                            result_.exit_register_types[instruction.offset] = Snapshot(state);
                        }
                        result_.exit_type_domains[instruction.offset] =
                            TypeDomain(state, instruction.offset);
                        if (options_.capture_register_domains) {
                            auto& registers = result_.exit_register_domains[instruction.offset];
                            registers.clear();
                            for (const auto& value : state)
                                registers.push_back(RegisterDomain(value, instruction.offset));
                        }
                    }
                    if (instruction.can_throw) {
                        for (const auto& region : code_.tries) {
                            const auto end = region.start_address +
                                             region.instruction_count;
                            if (instruction.offset < region.start_address ||
                                instruction.offset >= end) {
                                continue;
                            }
                            for (const auto& handler : region.handlers) {
                                enqueue(handler.address, before,
                                        instruction.offset);
                            }
                        }
                    }
                    for (const auto target : instruction.targets) {
                        enqueue(target, state, instruction.offset);
                    }

                    const auto next = instruction.offset + instruction.width;
                    const auto next_entry = index_by_offset_.find(next);
                    if (!HasFallthrough(instruction) ||
                        next_entry == index_by_offset_.end()) {
                        break;
                    }
                    if (instruction.kind == InstructionKind::ConditionalBranch ||
                        instruction.kind == InstructionKind::Switch ||
                        leaders_.contains(next)) {
                        enqueue(next, state, instruction.offset);
                        break;
                    }
                }
            }

            const auto unreachable = std::find_if(
                analyzed.begin(), analyzed.end(),
                [](const auto visited) { return !visited; });
            if (unreachable == analyzed.end()) break;
            const auto index = static_cast<std::size_t>(
                std::distance(analyzed.begin(), unreachable));
            entries[index] = RegisterState(code_.registers_size);
            queued[index] = true;
            worklist.push_back(index);
        }

        for (const auto handler : handler_offsets_) {
            const auto found = index_by_offset_.find(handler);
            if (found == index_by_offset_.end() ||
                instructions_[found->second]->opcode != 0x0dU) {
                AddIssue(handler, "catch handler does not begin with move-exception");
            }
        }
        return std::move(result_);
    }

private:
    RegisterTypeFrame Snapshot(const RegisterState& state) const {
        RegisterTypeFrame frame;
        frame.reserve(state.size());
        for (const auto& value : state) {
            RegisterTypeSnapshot out;
            out.descriptor = value.descriptor;
            out.uninitialized = value.uninitialized_id != 0U;
            switch (value.kind) {
                case ValueKind::Scalar32: out.kind = RegisterTypeKind::Scalar32; break;
                case ValueKind::Int32: out.kind = RegisterTypeKind::Int32; break;
                case ValueKind::Float32: out.kind = RegisterTypeKind::Float32; break;
                case ValueKind::Reference: out.kind = RegisterTypeKind::Reference; break;
                case ValueKind::LongLow: out.kind = RegisterTypeKind::LongLow; break;
                case ValueKind::DoubleLow: out.kind = RegisterTypeKind::DoubleLow; break;
                case ValueKind::LongHigh: case ValueKind::DoubleHigh:
                    out.kind = RegisterTypeKind::WideHigh; break;
                default: break;
            }
            // Only raw const definitions have a verifier-polymorphic value.
            // Never infer a constant from an int/float arithmetic result.
            if (value.kind == ValueKind::Scalar32 && !value.origins.empty()) {
                bool same = true;
                for (const auto origin : value.origins) {
                    const auto found = index_by_offset_.find(origin);
                    if (found == index_by_offset_.end() ||
                        !IsConst32(instructions_[found->second]->opcode)) { same = false; break; }
                    const auto bits = Literal32(*instructions_[found->second]);
                    if (out.constant32 && *out.constant32 != bits) { same = false; break; }
                    out.constant32 = bits;
                }
                if (!same) out.constant32.reset();
            }
            frame.push_back(std::move(out));
        }
        return frame;
    }

    static std::string RegisterDomain(const RegisterValue& value, std::uint32_t offset) {
        std::string signature;
        signature.push_back(static_cast<char>(value.kind));
        signature.push_back(value.kind == ValueKind::Scalar32 && value.all_zero ? 1 : 0);
        const auto size = static_cast<std::uint32_t>(value.descriptor.size());
        for (unsigned shift = 0; shift < 32U; shift += 8U)
            signature.push_back(static_cast<char>((size >> shift) & 255U));
        signature += value.descriptor;
        const bool private_domain = value.uninitialized_id != 0U ||
            value.kind == ValueKind::Unknown || value.kind == ValueKind::Conflict ||
            (value.kind == ValueKind::Reference && value.descriptor.empty());
        signature.push_back(private_domain ? 1 : 0);
        if (private_domain) for (unsigned shift = 0; shift < 32U; shift += 8U)
            signature.push_back(static_cast<char>((offset >> shift) & 255U));
        return signature;
    }

    std::string TypeDomain(const RegisterState& state, std::uint32_t offset) const {
        std::string signature;
        bool private_domain = false;
        for (std::size_t reg = 0U; reg < state.size(); ++reg) {
            if (options_.live_exit_registers != nullptr) {
                const auto& live = options_.live_exit_registers->at(offset);
                if (!std::binary_search(live.begin(), live.end(), reg)) continue;
            }
            if (std::find(options_.excluded_domain_registers.begin(),
                          options_.excluded_domain_registers.end(), reg) !=
                options_.excluded_domain_registers.end()) continue;
            const auto& value = state[reg];
            signature.push_back(static_cast<char>(reg & 0xffU));
            signature.push_back(static_cast<char>((reg >> 8U) & 0xffU));
            private_domain = private_domain || value.uninitialized_id != 0U ||
                value.kind == ValueKind::Unknown || value.kind == ValueKind::Conflict ||
                (value.kind == ValueKind::Reference && value.descriptor.empty());
            signature.push_back(static_cast<char>(value.kind));
            signature.push_back(value.kind == ValueKind::Scalar32 && value.all_zero ? 1 : 0);
            // Length-prefix descriptors; binary signatures cannot alias when
            // descriptor text contains digits or category delimiters.
            const auto size = static_cast<std::uint32_t>(value.descriptor.size());
            for (unsigned shift = 0U; shift < 32U; shift += 8U)
                signature.push_back(static_cast<char>((size >> shift) & 0xffU));
            signature += value.descriptor;
        }
        // Our category analysis does not prove the identity of unresolved or
        // uninitialized reference states. Never merge those dispatchers, even
        // when their textual class descriptors happen to match.
        signature.push_back(private_domain ? 1 : 0);
        if (private_domain) {
            for (unsigned shift = 0U; shift < 32U; shift += 8U)
                signature.push_back(static_cast<char>((offset >> shift) & 0xffU));
        }
        return signature;
    }

    static bool IsConst32(std::uint8_t opcode) {
        return opcode >= 0x12U && opcode <= 0x15U;
    }

    RegisterState EntryState() {
        RegisterState state(code_.registers_size);
        if (code_.ins_size > code_.registers_size) return state;
        auto cursor = static_cast<std::uint32_t>(code_.registers_size -
                                                code_.ins_size);
        constexpr std::uint32_t kStatic = 0x0008U;
        if ((encoded_.access_flags & kStatic) == 0U) {
            SetReference(state, cursor, dex_.descriptor(method_.class_idx));
            if (dex_.string(method_.name_idx) == "<init>")
                state[cursor].uninitialized_id = std::numeric_limits<std::uint32_t>::max();
            ++cursor;
        }
        const auto& proto = dex_.protos().at(method_.proto_idx);
        for (const auto type_idx : dex_.type_list(proto.parameters_off)) {
            const auto descriptor = dex_.descriptor(type_idx);
            SetDescriptor(state, cursor, descriptor);
            cursor += descriptor == "J" || descriptor == "D" ? 2U : 1U;
        }
        if (cursor != code_.registers_size) {
            AddIssue(0U, "method parameter words do not match ins_size");
        }
        return state;
    }

    void AddIssue(std::uint32_t offset, std::string message) {
        if (!issue_keys_.emplace(offset, message).second) return;
        result_.issues.push_back({offset, std::move(message)});
    }

    void Mark(const RegisterValue& value, ConstantUseType use,
              std::uint32_t offset) {
        for (const auto origin : value.origins) {
            auto origin_use = use;
            const bool zero = zero_constants_.contains(origin);
            if (origin_use == ConstantUseType::Reference && !zero) {
                AddIssue(offset, "non-zero const used as a reference");
                origin_use = ConstantUseType::Conflict;
            }
            auto& current = result_.constant_uses[origin];
            if (result_.polymorphic_zero_constants.contains(origin)) {
                continue;
            }
            if (current == ConstantUseType::Unconstrained) {
                current = origin_use;
                use_sites_[origin] = {origin_use, offset};
            } else if (current != origin_use && current != ConstantUseType::Conflict) {
                const auto scalar_use = [](const ConstantUseType type) {
                    return type == ConstantUseType::Int32 ||
                           type == ConstantUseType::Float32 ||
                           type == ConstantUseType::Reference;
                };
                if (zero && scalar_use(current) && scalar_use(origin_use)) {
                    // DEX uses a zero scalar as the null/reference value too.
                    // Keep the definition unclassified and let the lowering
                    // phase preserve the original const instruction.
                    current = ConstantUseType::Unconstrained;
                    result_.polymorphic_zero_constants.insert(origin);
                    continue;
                }
                current = ConstantUseType::Conflict;
                const auto first = use_sites_.find(origin);
                const auto type_name = [](ConstantUseType type) {
                    switch (type) {
                        case ConstantUseType::Int32: return "int";
                        case ConstantUseType::Float32: return "float";
                        case ConstantUseType::Reference: return "reference";
                        case ConstantUseType::Conflict: return "conflict";
                        case ConstantUseType::Unconstrained: return "unconstrained";
                    }
                    return "unknown";
                };
                AddIssue(offset,
                         "const at code-unit " + std::to_string(origin) +
                             " reaches incompatible typed uses (" +
                             (first == use_sites_.end() ? "unknown" :
                                 type_name(first->second.first)) +
                             " first at " +
                             std::to_string(first == use_sites_.end() ? 0U :
                                                first->second.second) + ", " +
                             type_name(origin_use) + " at " +
                             std::to_string(offset) + ")");
            }
        }
    }

    void MarkReferenceDescriptor(const RegisterValue& value,
                                 std::string_view descriptor) {
        if (!IsReferenceDescriptor(descriptor)) {
            return;
        }
        for (const auto origin : value.origins) {
            if (zero_constants_.contains(origin)) {
                result_.constant_reference_descriptors[origin].emplace(descriptor);
            }
        }
    }

    bool CheckRegister(std::uint32_t reg, std::uint32_t offset,
                       std::string_view role) {
        if (reg < code_.registers_size) return true;
        AddIssue(offset, std::string(role) + " register is out of bounds");
        return false;
    }

    void Require(RegisterState& state, std::uint32_t reg,
                 ExpectedType expected, std::uint32_t offset,
                 std::string_view role) {
        if (!CheckRegister(reg, offset, role)) return;
        auto& value = state[reg];
        if (value.kind == ValueKind::Unknown) {
            if (!value.origins.empty()) {
                const auto use = expected == ExpectedType::Float32 ?
                    ConstantUseType::Float32 :
                    expected == ExpectedType::Reference ?
                        ConstantUseType::Reference : ConstantUseType::Int32;
                Mark(value, use, offset);
            }
            return;
        }
        if (value.kind == ValueKind::Undefined) {
            AddIssue(offset, std::string(role) + " uses an undefined register");
            return;
        }
        const auto mismatch = [&]() {
            AddIssue(offset, std::string(role) + " register v" +
                                 std::to_string(reg) +
                                 " has an incompatible register type" +
                                 (value.descriptor.empty() ? std::string{} :
                                  " (" + value.descriptor + ")"));
        };
        switch (expected) {
            case ExpectedType::Int32:
                if (value.kind == ValueKind::Scalar32 || value.kind == ValueKind::Int32) {
                    Mark(value, ConstantUseType::Int32, offset);
                } else if (value.kind != ValueKind::Int32) {
                    mismatch();
                }
                break;
            case ExpectedType::Float32:
                if (value.kind == ValueKind::Scalar32 || value.kind == ValueKind::Float32) {
                    Mark(value, ConstantUseType::Float32, offset);
                } else if (value.kind != ValueKind::Float32) {
                    mismatch();
                }
                break;
            case ExpectedType::Reference:
                if (value.kind == ValueKind::Scalar32 || value.kind == ValueKind::Reference) {
                    Mark(value, ConstantUseType::Reference, offset);
                } else if (value.kind != ValueKind::Reference) {
                    mismatch();
                }
                break;
            case ExpectedType::Long:
                if (value.kind != ValueKind::LongLow &&
                    value.kind != ValueKind::Scalar64Low) {
                    mismatch();
                }
                RequireWideHigh(state, reg, ValueKind::LongHigh, offset, role);
                break;
            case ExpectedType::Double:
                if (value.kind != ValueKind::DoubleLow &&
                    value.kind != ValueKind::Scalar64Low) {
                    mismatch();
                }
                RequireWideHigh(state, reg, ValueKind::DoubleHigh, offset, role);
                break;
        }
    }

    void RequireWideHigh(RegisterState& state, std::uint32_t reg,
                         ValueKind expected, std::uint32_t offset,
                         std::string_view role) {
        if (!CheckRegister(reg + 1U, offset, role)) return;
        const auto high = state[reg + 1U].kind;
        if (high != expected && high != ValueKind::Scalar64High &&
            high != ValueKind::Unknown) {
            AddIssue(offset, std::string(role) +
                                 " does not contain a valid wide register pair");
        }
    }

    void RequireDescriptor(RegisterState& state, std::uint32_t reg,
                           std::string_view descriptor, std::uint32_t offset,
                           std::string_view role) {
        if (descriptor == "F") {
            Require(state, reg, ExpectedType::Float32, offset, role);
        } else if (descriptor == "J") {
            Require(state, reg, ExpectedType::Long, offset, role);
        } else if (descriptor == "D") {
            Require(state, reg, ExpectedType::Double, offset, role);
        } else if (IsReferenceDescriptor(descriptor)) {
            if (reg < state.size()) {
                MarkReferenceDescriptor(state[reg], descriptor);
            }
            Require(state, reg, ExpectedType::Reference, offset, role);
            if (reg < state.size() &&
                state[reg].kind == ValueKind::Reference &&
                state[reg].descriptor == "Ljava/lang/Object;" &&
                descriptor != "Ljava/lang/Object;") {
                AddIssue(offset, std::string(role) +
                                     " has java.lang.Object where " +
                                     std::string(descriptor) + " is required");
            }
        } else {
            Require(state, reg, ExpectedType::Int32, offset, role);
        }
    }

    void SetValue(RegisterState& state, std::uint32_t reg,
                  RegisterValue value, std::uint32_t offset = 0U) {
        if (!CheckRegister(reg, offset, "destination")) return;
        state[reg] = std::move(value);
    }

    void SetReference(RegisterState& state, std::uint32_t reg,
                      std::string descriptor, std::uint32_t offset = 0U) {
        SetValue(state, reg,
                 {ValueKind::Reference, std::move(descriptor), {}, false},
                 offset);
    }

    void SetWide(RegisterState& state, std::uint32_t reg, ValueKind low,
                 ValueKind high, std::uint32_t offset) {
        SetValue(state, reg, {low, {}, {}, false}, offset);
        SetValue(state, reg + 1U, {high, {}, {}, false}, offset);
    }

    void SetDescriptor(RegisterState& state, std::uint32_t reg,
                       std::string_view descriptor, std::uint32_t offset = 0U) {
        if (descriptor == "F") {
            SetValue(state, reg, {ValueKind::Float32, {}, {}, false}, offset);
        } else if (descriptor == "J") {
            SetWide(state, reg, ValueKind::LongLow, ValueKind::LongHigh, offset);
        } else if (descriptor == "D") {
            SetWide(state, reg, ValueKind::DoubleLow, ValueKind::DoubleHigh,
                    offset);
        } else if (IsReferenceDescriptor(descriptor)) {
            SetReference(state, reg, std::string(descriptor), offset);
        } else {
            SetValue(state, reg, {ValueKind::Int32, {}, {}, false}, offset);
        }
    }

    static std::uint32_t Literal32(const DecodedInstruction& instruction) {
        const auto first = instruction.code_units.front();
        if (instruction.opcode == 0x12U) {
            auto value = static_cast<std::int32_t>((first >> 12U) & 0x0fU);
            if ((value & 8) != 0) value |= ~0x0f;
            return static_cast<std::uint32_t>(value);
        }
        if (instruction.opcode == 0x13U) {
            return static_cast<std::uint32_t>(static_cast<std::int32_t>(
                static_cast<std::int16_t>(instruction.code_units.at(1U))));
        }
        if (instruction.opcode == 0x14U) {
            return static_cast<std::uint32_t>(instruction.code_units.at(1U)) |
                   static_cast<std::uint32_t>(instruction.code_units.at(2U))
                       << 16U;
        }
        return static_cast<std::uint32_t>(instruction.code_units.at(1U))
               << 16U;
    }

    std::string ArrayElementDescriptor(const RegisterState& state,
                                       std::uint32_t reg) const {
        if (reg >= state.size()) return {};
        const auto& value = state[reg];
        if (value.kind != ValueKind::Reference || value.descriptor.size() < 2U ||
            value.descriptor.front() != '[') {
            return {};
        }
        return value.descriptor.substr(1U);
    }

    std::optional<std::string> ResultDescriptor(std::size_t index) {
        if (index == 0U) return std::nullopt;
        const auto& current = *instructions_[index];
        const auto& previous = *instructions_[index - 1U];
        if (previous.offset + previous.width != current.offset) return std::nullopt;
        if (previous.opcode == 0x24U || previous.opcode == 0x25U) {
            const auto type_idx = previous.code_units.at(1U);
            if (type_idx >= dex_.types().size()) return std::nullopt;
            return dex_.descriptor(type_idx);
        }
        if ((previous.opcode >= 0x6eU && previous.opcode <= 0x72U) ||
            (previous.opcode >= 0x74U && previous.opcode <= 0x78U) ||
            previous.opcode == 0xfaU || previous.opcode == 0xfbU) {
            const auto method_idx = previous.code_units.at(1U);
            if (method_idx >= dex_.methods().size()) return std::nullopt;
            return dex_.descriptor(dex_.protos().at(
                dex_.methods().at(method_idx).proto_idx).return_type_idx);
        }
        // invoke-custom return types require decoding the call-site encoded
        // array. Treat them as unknown here while still checking adjacency.
        if (previous.opcode == 0xfcU || previous.opcode == 0xfdU) return "?";
        return std::nullopt;
    }

    std::vector<std::uint32_t> InvokeRegisters(
        const DecodedInstruction& instruction) {
        std::vector<std::uint32_t> registers;
        const auto first = instruction.code_units.front();
        const auto range = (instruction.opcode >= 0x74U &&
                            instruction.opcode <= 0x78U) ||
                           instruction.opcode == 0x25U ||
                           instruction.opcode == 0xfbU ||
                           instruction.opcode == 0xfdU;
        if (range) {
            const auto count = static_cast<std::uint32_t>(first >> 8U);
            const auto start = static_cast<std::uint32_t>(
                instruction.code_units.at(2U));
            registers.reserve(count);
            for (std::uint32_t word = 0U; word < count; ++word) {
                registers.push_back(start + word);
            }
            return registers;
        }
        const auto count = static_cast<std::uint32_t>(first >> 12U);
        const auto packed = instruction.code_units.at(2U);
        const std::array<std::uint32_t, 5U> values{
            static_cast<std::uint32_t>(packed & 0x0fU),
            static_cast<std::uint32_t>((packed >> 4U) & 0x0fU),
            static_cast<std::uint32_t>((packed >> 8U) & 0x0fU),
            static_cast<std::uint32_t>((packed >> 12U) & 0x0fU),
            static_cast<std::uint32_t>((first >> 8U) & 0x0fU),
        };
        if (count > values.size()) {
            AddIssue(instruction.offset, "invoke-35c argument count exceeds five words");
            return registers;
        }
        registers.assign(values.begin(), values.begin() + count);
        return registers;
    }

    void CheckInvoke(const DecodedInstruction& instruction,
                     RegisterState& state) {
        const auto registers = InvokeRegisters(instruction);
        if (registers.size() > code_.outs_size) {
            AddIssue(instruction.offset,
                     "invoke argument word count exceeds outs_size");
        }
        if (instruction.opcode == 0xfcU || instruction.opcode == 0xfdU) {
            for (const auto reg : registers) {
                if (!CheckRegister(reg, instruction.offset, "invoke-custom argument"))
                    return;
            }
            return;
        }
        const auto method_idx = instruction.code_units.at(1U);
        if (method_idx >= dex_.methods().size()) {
            AddIssue(instruction.offset, "invoke method index is out of bounds");
            return;
        }
        const auto is_static = instruction.opcode == 0x71U ||
                               instruction.opcode == 0x77U;
        std::vector<std::string> expected;
        if (!is_static) {
            expected.push_back(dex_.descriptor(
                dex_.methods().at(method_idx).class_idx));
        }
        std::uint32_t proto_idx = dex_.methods().at(method_idx).proto_idx;
        if ((instruction.opcode == 0xfaU || instruction.opcode == 0xfbU) &&
            instruction.code_units.size() >= 4U) {
            proto_idx = instruction.code_units.at(3U);
        }
        if (proto_idx >= dex_.protos().size()) {
            AddIssue(instruction.offset, "invoke proto index is out of bounds");
            return;
        }
        for (const auto type_idx : dex_.type_list(
                 dex_.protos().at(proto_idx).parameters_off)) {
            expected.push_back(dex_.descriptor(type_idx));
        }
        std::size_t word = 0U;
        for (const auto& descriptor : expected) {
            if (word >= registers.size()) {
                AddIssue(instruction.offset,
                         "invoke register words do not match target prototype");
                return;
            }
            RequireDescriptor(state, registers[word], descriptor,
                              instruction.offset, "invoke argument");
            const auto width = descriptor == "J" || descriptor == "D" ? 2U : 1U;
            if (width == 2U) {
                if (word + 1U >= registers.size() ||
                    registers[word + 1U] != registers[word] + 1U) {
                    AddIssue(instruction.offset,
                             "wide invoke argument is not an adjacent register pair");
                    return;
                }
            }
            word += width;
        }
        if (word != registers.size()) {
            AddIssue(instruction.offset,
                     "invoke register words do not match target prototype");
        }
        if ((instruction.opcode == 0x70U || instruction.opcode == 0x76U) &&
            dex_.string(dex_.methods().at(method_idx).name_idx) == "<init>" &&
            !registers.empty() && registers.front() < state.size()) {
            const auto id = state[registers.front()].uninitialized_id;
            if (id != 0U && id != std::numeric_limits<std::uint32_t>::max() - 1U) {
                for (auto& value : state)
                    if (value.uninitialized_id == id) value.uninitialized_id = 0U;
            }
        }
    }

    void Transfer(std::size_t index, RegisterState& state) {
        const auto& instruction = *instructions_[index];
        const auto opcode = instruction.opcode;
        const auto first = instruction.code_units.front();
        const auto a8 = static_cast<std::uint32_t>(first >> 8U);
        const auto a4 = static_cast<std::uint32_t>((first >> 8U) & 0x0fU);
        const auto b4 = static_cast<std::uint32_t>(first >> 12U);
        const auto pair = instruction.code_units.size() > 1U ?
            instruction.code_units[1U] : 0U;
        const auto b8 = static_cast<std::uint32_t>(pair & 0xffU);
        const auto c8 = static_cast<std::uint32_t>(pair >> 8U);

        if (opcode >= 0x01U && opcode <= 0x09U) {
          std::uint32_t destination = a4;
          std::uint32_t source = b4;
          const auto form = (opcode - 1U) % 3U;
          if (form == 1U) {
            destination = a8;
            source = instruction.code_units.at(1U);
          } else if (form == 2U) {
            destination = instruction.code_units.at(1U);
            source = instruction.code_units.at(2U);
          }
          const auto family = (opcode - 1U) / 3U;
          if (family == 0U) {
            if (CheckRegister(source, instruction.offset, "move source")) {
              const auto kind = state[source].kind;
              if (kind == ValueKind::Undefined) {
                AddIssue(instruction.offset,
                         "move source uses an undefined register");
              } else if (kind == ValueKind::Reference ||
                         kind == ValueKind::Scalar64Low ||
                         kind == ValueKind::Scalar64High ||
                         kind == ValueKind::LongLow ||
                         kind == ValueKind::LongHigh ||
                         kind == ValueKind::DoubleLow ||
                         kind == ValueKind::DoubleHigh) {
                AddIssue(instruction.offset,
                         "move source has an incompatible register type");
              }
              SetValue(state, destination, state[source], instruction.offset);
            }
          } else if (family == 1U) {
            if (CheckRegister(source, instruction.offset, "move-wide source") &&
                CheckRegister(source + 1U, instruction.offset,
                              "move-wide source")) {
              const auto low = state[source];
              const auto high = state[source + 1U];
              const auto valid_pair = (low.kind == ValueKind::Scalar64Low &&
                                       high.kind == ValueKind::Scalar64High) ||
                                      (low.kind == ValueKind::LongLow &&
                                       high.kind == ValueKind::LongHigh) ||
                                      (low.kind == ValueKind::DoubleLow &&
                                       high.kind == ValueKind::DoubleHigh) ||
                                      (low.kind == ValueKind::Unknown &&
                                       high.kind == ValueKind::Unknown);
              if (!valid_pair) {
                AddIssue(instruction.offset,
                         "move-wide source is undefined or not a wide pair");
              }
              SetValue(state, destination, low, instruction.offset);
              SetValue(state, destination + 1U, high, instruction.offset);
            }
          } else {
            Require(state, source, ExpectedType::Reference, instruction.offset,
                    "move-object source");
            if (CheckRegister(source, instruction.offset,
                              "move-object source")) {
              auto value = state[source];
              // A zero moved with move-object is still the null constant,
              // not an arbitrary reference. Widening it here loses the array
              // descriptor when this path joins a typed array path.
              SetValue(state, destination, std::move(value),
                       instruction.offset);
            }
          }
          return;
        }
        if (opcode >= 0x0aU && opcode <= 0x0cU) {
            const auto descriptor = ResultDescriptor(index);
            if (!descriptor.has_value()) {
                AddIssue(instruction.offset,
                         "move-result is not immediately after a result-producing instruction");
                SetValue(state, a8, {ValueKind::Unknown, {}, {}, false},
                         instruction.offset);
                return;
            }
            if (*descriptor == "?") {
                SetValue(state, a8, {ValueKind::Unknown, {}, {}, false},
                         instruction.offset);
                return;
            }
            const auto expected_opcode = *descriptor == "J" || *descriptor == "D" ?
                0x0bU : IsReferenceDescriptor(*descriptor) ? 0x0cU : 0x0aU;
            if (opcode != expected_opcode || *descriptor == "V") {
                AddIssue(instruction.offset,
                         "move-result opcode does not match the producer return type");
            }
            SetDescriptor(state, a8, *descriptor, instruction.offset);
            return;
        }
        if (opcode == 0x0dU) {
            if (!handler_offsets_.contains(instruction.offset)) {
                AddIssue(instruction.offset,
                         "move-exception is outside a catch handler entry");
            }
            SetReference(state, a8, "Ljava/lang/Throwable;", instruction.offset);
            return;
        }
        if (opcode >= 0x0eU && opcode <= 0x11U) {
            const auto return_descriptor = dex_.descriptor(
                dex_.protos().at(method_.proto_idx).return_type_idx);
            if (opcode == 0x0eU) {
                if (return_descriptor != "V") {
                    AddIssue(instruction.offset,
                             "return-void used by a non-void method");
                }
            } else {
                const auto expected_opcode = return_descriptor == "J" ||
                    return_descriptor == "D" ? 0x10U :
                    IsReferenceDescriptor(return_descriptor) ? 0x11U : 0x0fU;
                if (opcode != expected_opcode || return_descriptor == "V") {
                    AddIssue(instruction.offset,
                             "return opcode does not match method return type");
                }
                RequireDescriptor(state, a8, return_descriptor,
                                  instruction.offset, "return value");
            }
            return;
        }
        if (IsConst32(opcode)) {
            const auto destination = opcode == 0x12U ? a4 : a8;
            const auto bits = Literal32(instruction);
            SetValue(state, destination,
                     {ValueKind::Scalar32, {}, {instruction.offset}, bits == 0U},
                     instruction.offset);
            return;
        }
        if (opcode >= 0x16U && opcode <= 0x19U) {
            SetWide(state, a8, ValueKind::Scalar64Low,
                    ValueKind::Scalar64High, instruction.offset);
            return;
        }
        if (opcode == 0x1aU || opcode == 0x1bU) {
            SetReference(state, a8, "Ljava/lang/String;", instruction.offset);
            return;
        }
        if (opcode == 0x1cU) {
            SetReference(state, a8, "Ljava/lang/Class;", instruction.offset);
            return;
        }
        if (opcode == 0x1dU || opcode == 0x1eU || opcode == 0x27U) {
            Require(state, a8, ExpectedType::Reference, instruction.offset,
                    opcode == 0x27U ? "throw value" : "monitor value");
            return;
        }
        if (opcode == 0x1fU) {
            Require(state, a8, ExpectedType::Reference, instruction.offset,
                    "check-cast value");
            const auto type_idx = instruction.code_units.at(1U);
            if (type_idx < dex_.types().size()) {
                SetReference(state, a8, dex_.descriptor(type_idx),
                             instruction.offset);
            }
            return;
        }
        if (opcode == 0x20U) {
            Require(state, b4, ExpectedType::Reference, instruction.offset,
                    "instance-of value");
            SetValue(state, a4, {ValueKind::Int32, {}, {}, false},
                     instruction.offset);
            return;
        }
        if (opcode == 0x21U) {
            Require(state, b4, ExpectedType::Reference, instruction.offset,
                    "array-length value");
            SetValue(state, a4, {ValueKind::Int32, {}, {}, false},
                     instruction.offset);
            return;
        }
        if (opcode == 0x22U) {
            const auto type_idx = instruction.code_units.at(1U);
            SetReference(state, a8,
                         type_idx < dex_.types().size() ?
                             dex_.descriptor(type_idx) : std::string{},
                         instruction.offset);
            if (a8 < state.size()) state[a8].uninitialized_id = instruction.offset + 1U;
            return;
        }
        if (opcode == 0x23U) {
            Require(state, b4, ExpectedType::Int32, instruction.offset,
                    "new-array size");
            const auto type_idx = instruction.code_units.at(1U);
            SetReference(state, a4,
                         type_idx < dex_.types().size() ?
                             dex_.descriptor(type_idx) : std::string{},
                         instruction.offset);
            return;
        }
        if (opcode == 0x24U || opcode == 0x25U) {
            const auto registers = InvokeRegisters(instruction);
            const auto type_idx = instruction.code_units.at(1U);
            const auto array = type_idx < dex_.types().size() ?
                dex_.descriptor(type_idx) : std::string{};
            const auto element = array.size() > 1U && array.front() == '[' ?
                array.substr(1U) : std::string{};
            for (const auto reg : registers) {
                RequireDescriptor(state, reg, element, instruction.offset,
                                  "filled-new-array element");
            }
            return;
        }
        if (opcode == 0x26U) {
            Require(state, a8, ExpectedType::Reference, instruction.offset,
                    "fill-array-data array");
            return;
        }
        if (opcode == 0x2bU || opcode == 0x2cU) {
            Require(state, a8, ExpectedType::Int32, instruction.offset,
                    "switch selector");
            return;
        }
        if (opcode >= 0x2dU && opcode <= 0x31U) {
            const auto expected = opcode <= 0x2eU ? ExpectedType::Float32 :
                                  opcode <= 0x30U ? ExpectedType::Double :
                                                   ExpectedType::Long;
            Require(state, b8, expected, instruction.offset, "compare left");
            Require(state, c8, expected, instruction.offset, "compare right");
            SetValue(state, a8, {ValueKind::Int32, {}, {}, false},
                     instruction.offset);
            return;
        }
        if (opcode >= 0x32U && opcode <= 0x37U) {
            if (opcode <= 0x33U && b4 < state.size() && a4 < state.size() &&
                (state[a4].kind == ValueKind::Reference ||
                 state[b4].kind == ValueKind::Reference)) {
                Require(state, a4, ExpectedType::Reference, instruction.offset,
                        "reference comparison");
                Require(state, b4, ExpectedType::Reference, instruction.offset,
                        "reference comparison");
            } else {
                Require(state, a4, ExpectedType::Int32, instruction.offset,
                        "integer comparison");
                Require(state, b4, ExpectedType::Int32, instruction.offset,
                        "integer comparison");
            }
            return;
        }
        if (opcode >= 0x38U && opcode <= 0x3dU) {
            if (opcode >= 0x3aU) {
                Require(state, a8, ExpectedType::Int32, instruction.offset,
                        "zero comparison");
            } else if (CheckRegister(a8, instruction.offset,
                                     "zero comparison")) {
                const auto kind = state[a8].kind;
                if (kind == ValueKind::Undefined) {
                    AddIssue(instruction.offset,
                             "zero comparison uses an undefined register");
                } else if (kind == ValueKind::Conflict ||
                           kind == ValueKind::Unknown ||
                           kind == ValueKind::Float32 ||
                           kind == ValueKind::Scalar64Low ||
                           kind == ValueKind::Scalar64High ||
                           kind == ValueKind::LongLow ||
                           kind == ValueKind::LongHigh ||
                           kind == ValueKind::DoubleLow ||
                           kind == ValueKind::DoubleHigh) {
                    AddIssue(instruction.offset,
                             "zero comparison has an incompatible register type: v" +
                                 std::to_string(a8) + " is " +
                                 std::string(ValueKindName(kind)) +
                                 (state[a8].descriptor.empty() ? "" :
                                     " (" + state[a8].descriptor + ")"));
                } else {
                    // eqz/nez accepts a polymorphic literal zero, not a
                    // typed float zero. Record this consumer even for #0:
                    // another float consumer must make its definition
                    // polymorphic instead of selecting a float-only helper.
                    Mark(state[a8], kind == ValueKind::Reference ?
                             ConstantUseType::Reference : ConstantUseType::Int32,
                         instruction.offset);
                }
            }
            return;
        }
        if (opcode >= 0x44U && opcode <= 0x51U) {
            Require(state, b8, ExpectedType::Reference, instruction.offset,
                    "array operand");
            Require(state, c8, ExpectedType::Int32, instruction.offset,
                    "array index");
            const auto element = ArrayElementDescriptor(state, b8);
            if (opcode <= 0x4aU) {
                if (opcode == 0x45U) {
                    if (element == "D") {
                        SetDescriptor(state, a8, "D", instruction.offset);
                    } else if (element == "J") {
                        SetDescriptor(state, a8, "J", instruction.offset);
                    } else {
                        // The verifier tracks aget-wide as a category-2
                        // value even when the array descriptor was widened by
                        // a CFG merge. Do not guess long here: a double array
                        // is equally valid and the guessed kind poisons every
                        // later double operation.
                        SetWide(state, a8, ValueKind::Scalar64Low,
                                ValueKind::Scalar64High, instruction.offset);
                    }
                } else if (opcode == 0x46U) {
                    SetReference(state, a8, element, instruction.offset);
                } else if (opcode == 0x44U && element == "F") {
                    SetDescriptor(state, a8, "F", instruction.offset);
                } else {
                    SetDescriptor(state, a8, "I", instruction.offset);
                }
            } else if (opcode == 0x4cU) {
                if (element == "D" || element == "J") {
                    RequireDescriptor(state, a8, element, instruction.offset,
                                      "array value");
                } else {
                    Require(state, a8, ExpectedType::Long, instruction.offset,
                            "array value");
                }
            } else if (opcode == 0x4dU) {
                Require(state, a8, ExpectedType::Reference, instruction.offset,
                        "array value");
            } else if (opcode == 0x4bU && element == "F") {
                Require(state, a8, ExpectedType::Float32, instruction.offset,
                        "array value");
            } else {
                Require(state, a8, ExpectedType::Int32, instruction.offset,
                        "array value");
            }
            return;
        }
        if (opcode >= 0x52U && opcode <= 0x6dU) {
            const auto field_idx = instruction.code_units.at(1U);
            if (field_idx >= dex_.fields().size()) {
                AddIssue(instruction.offset, "field index is out of bounds");
                return;
            }
            const auto descriptor = dex_.descriptor(
                dex_.fields().at(field_idx).type_idx);
            const auto instance = opcode <= 0x5fU;
            const auto put = (opcode >= 0x59U && opcode <= 0x5fU) ||
                             opcode >= 0x67U;
            if (instance) {
                Require(state, b4, ExpectedType::Reference, instruction.offset,
                        "instance field receiver");
            }
            const auto value_reg = instance ? a4 : a8;
            if (put) {
                RequireDescriptor(state, value_reg, descriptor,
                                  instruction.offset, "field value");
            } else {
                SetDescriptor(state, value_reg, descriptor, instruction.offset);
            }
            return;
        }
        if ((opcode >= 0x6eU && opcode <= 0x72U) ||
            (opcode >= 0x74U && opcode <= 0x78U) ||
            (opcode >= 0xfaU && opcode <= 0xfdU)) {
            CheckInvoke(instruction, state);
            return;
        }
        if (opcode >= 0x7bU && opcode <= 0x8fU) {
            if (opcode <= 0x7cU) {
                Require(state, b4, ExpectedType::Int32, instruction.offset,
                        "unary input");
                SetDescriptor(state, a4, "I", instruction.offset);
            } else if (opcode <= 0x7eU) {
                Require(state, b4, ExpectedType::Long, instruction.offset,
                        "unary input");
                SetDescriptor(state, a4, "J", instruction.offset);
            } else if (opcode == 0x7fU) {
                Require(state, b4, ExpectedType::Float32, instruction.offset,
                        "unary input");
                SetDescriptor(state, a4, "F", instruction.offset);
            } else if (opcode == 0x80U) {
                Require(state, b4, ExpectedType::Double, instruction.offset,
                        "unary input");
                SetDescriptor(state, a4, "D", instruction.offset);
            } else {
                static constexpr std::array<std::string_view, 15U> sources{
                    "I", "I", "I", "J", "J", "J", "F", "F", "F",
                    "D", "D", "D", "I", "I", "I"};
                static constexpr std::array<std::string_view, 15U> targets{
                    "J", "F", "D", "I", "F", "D", "I", "J", "D",
                    "I", "J", "F", "I", "I", "I"};
                const auto slot = static_cast<std::size_t>(opcode - 0x81U);
                RequireDescriptor(state, b4, sources[slot], instruction.offset,
                                  "conversion input");
                SetDescriptor(state, a4, targets[slot], instruction.offset);
            }
            return;
        }
        if (opcode >= 0x90U && opcode <= 0xafU) {
            std::string_view left = "I";
            std::string_view right = "I";
            std::string_view output = "I";
            if (opcode >= 0x9bU && opcode <= 0xa5U) {
                left = "J";
                right = opcode >= 0xa3U ? "I" : "J";
                output = "J";
            } else if (opcode >= 0xa6U && opcode <= 0xaaU) {
                left = right = output = "F";
            } else if (opcode >= 0xabU) {
                left = right = output = "D";
            }
            RequireDescriptor(state, b8, left, instruction.offset,
                              "binary left operand");
            RequireDescriptor(state, c8, right, instruction.offset,
                              "binary right operand");
            SetDescriptor(state, a8, output, instruction.offset);
            return;
        }
        if (opcode >= 0xb0U && opcode <= 0xcfU) {
            std::string_view left = "I";
            std::string_view right = "I";
            std::string_view output = "I";
            if (opcode >= 0xbbU && opcode <= 0xc5U) {
                left = "J";
                right = opcode >= 0xc3U ? "I" : "J";
                output = "J";
            } else if (opcode >= 0xc6U && opcode <= 0xcaU) {
                left = right = output = "F";
            } else if (opcode >= 0xcbU) {
                left = right = output = "D";
            }
            RequireDescriptor(state, a4, left, instruction.offset,
                              "two-address left operand");
            RequireDescriptor(state, b4, right, instruction.offset,
                              "two-address right operand");
            SetDescriptor(state, a4, output, instruction.offset);
            return;
        }
        if (opcode >= 0xd0U && opcode <= 0xe2U) {
            const auto source = opcode <= 0xd7U ? b4 : b8;
            Require(state, source, ExpectedType::Int32, instruction.offset,
                    "literal arithmetic input");
            SetDescriptor(state, opcode <= 0xd7U ? a4 : a8, "I",
                          instruction.offset);
            return;
        }
        if (opcode == 0xfeU) {
            SetReference(state, a8, "Ljava/lang/invoke/MethodHandle;",
                         instruction.offset);
        } else if (opcode == 0xffU) {
            SetReference(state, a8, "Ljava/lang/invoke/MethodType;",
                         instruction.offset);
        }
    }

    bool MergeState(RegisterState& target, const RegisterState& incoming,
                    std::uint32_t offset) {
        bool changed = false;
        for (std::size_t reg = 0U; reg < target.size(); ++reg) {
            auto merged = MergeValue(target[reg], incoming[reg], offset);
            if (!(merged == target[reg])) {
                target[reg] = std::move(merged);
                changed = true;
            }
        }
        return changed;
    }

    RegisterValue MergeValue(const RegisterValue& left,
                             const RegisterValue& right,
                             std::uint32_t offset) {
        if (left == right) return left;
        if (left.kind == ValueKind::Undefined &&
            right.kind == ValueKind::Undefined) {
            return left;
        }
        if (left.kind == ValueKind::Conflict ||
            right.kind == ValueKind::Conflict) {
            return {ValueKind::Conflict,
                    !left.descriptor.empty() ? left.descriptor :
                                               right.descriptor,
                    {}, false};
        }
        if (left.kind == ValueKind::Undefined ||
            right.kind == ValueKind::Undefined) {
            return {ValueKind::Conflict,
                    "undefined merge from 0x" + std::to_string(offset),
                    {}, false};
        }
        // A typed value at a join does not erase the raw constants on the
        // other incoming edge. Their consumers still decide which helper
        // may replace each definition. Do not eagerly classify dead merges.
        const auto with_origins = [&](RegisterValue result) {
            if (left.uninitialized_id != right.uninitialized_id)
                result.uninitialized_id = std::numeric_limits<std::uint32_t>::max() - 1U;
            result.origins = left.origins;
            result.origins.insert(result.origins.end(), right.origins.begin(),
                                  right.origins.end());
            std::sort(result.origins.begin(), result.origins.end());
            result.origins.erase(std::unique(result.origins.begin(), result.origins.end()),
                                 result.origins.end());
            result.all_zero = left.all_zero && right.all_zero;
            return result;
        };
        if (left.kind == ValueKind::Unknown || right.kind == ValueKind::Unknown) {
            return with_origins({ValueKind::Unknown, {}, {}, false});
        }
        if (left.kind == ValueKind::Scalar32 &&
            right.kind == ValueKind::Scalar32) {
            return with_origins({ValueKind::Scalar32, {}, {}, false});
        }
        if (left.kind == ValueKind::Scalar32) {
            if (right.kind == ValueKind::Reference && !left.all_zero) {
                return {ValueKind::Conflict,
                        "scalar/reference merge from 0x" +
                            std::to_string(offset), {}, false};
            }
            if (right.kind == ValueKind::Reference || right.kind == ValueKind::Int32 ||
                right.kind == ValueKind::Float32) return with_origins(right);
        }
        if (right.kind == ValueKind::Scalar32) {
            if (left.kind == ValueKind::Reference && !right.all_zero) {
                return {ValueKind::Conflict,
                        "reference/scalar merge from 0x" +
                            std::to_string(offset), {}, false};
            }
            if (left.kind == ValueKind::Reference || left.kind == ValueKind::Int32 ||
                left.kind == ValueKind::Float32) return with_origins(left);
        }
        if (left.kind == right.kind) {
            auto result = left;
            if (left.kind == ValueKind::Reference &&
                left.descriptor != right.descriptor) {
                result.descriptor.clear();
            }
            return with_origins(std::move(result));
        }
        if (left.kind == ValueKind::Scalar64Low &&
            (right.kind == ValueKind::LongLow ||
             right.kind == ValueKind::DoubleLow)) {
            return right;
        }
        if (right.kind == ValueKind::Scalar64Low &&
            (left.kind == ValueKind::LongLow ||
             left.kind == ValueKind::DoubleLow)) {
            return left;
        }
        if (left.kind == ValueKind::Scalar64High &&
            (right.kind == ValueKind::LongHigh ||
             right.kind == ValueKind::DoubleHigh)) {
            return right;
        }
        if (right.kind == ValueKind::Scalar64High &&
            (left.kind == ValueKind::LongHigh ||
             left.kind == ValueKind::DoubleHigh)) {
            return left;
        }
        return {ValueKind::Conflict,
                "typed merge from code-unit " + std::to_string(offset) +
                    ": " + std::string(ValueKindName(left.kind)) + " / " +
                    std::string(ValueKindName(right.kind)), {}, false};
    }

    static bool HasFallthrough(const DecodedInstruction& instruction) {
        return instruction.kind != InstructionKind::UnconditionalBranch &&
               instruction.kind != InstructionKind::Return &&
               instruction.kind != InstructionKind::Throw;
    }

    const DexFile& dex_;
    const DexEncodedMethod& encoded_;
    const CodeItem& code_;
    const DexMethodId& method_;
    MethodTypeAnalysisOptions options_;
    std::set<std::uint32_t> capture_exit_offsets_;
    MethodTypeAnalysis result_;
    std::set<std::uint32_t> zero_constants_;
    std::vector<const DecodedInstruction*> instructions_;
    std::map<std::uint32_t, std::size_t> index_by_offset_;
    std::set<std::uint32_t> handler_offsets_;
    std::set<std::uint32_t> leaders_;
    std::set<std::pair<std::uint32_t, std::string>> issue_keys_;
    std::map<std::uint32_t,
             std::pair<ConstantUseType, std::uint32_t>> use_sites_;
};

} // namespace

MethodTypeAnalysis AnalyzeMethodTypes(const DexFile& dex,
                                      const DexEncodedMethod& method,
                                      const CodeItem& code,
                                      MethodTypeAnalysisOptions options) {
    return MethodAnalyzer(dex, method, code, options).Run();
}

} // namespace birch::dex
