#include "birch/dex/builder.h"
#include "birch/dex/verifier.h"
#include "cff_type_domains.h"
#include "birch/dex/liveness.h"
#include "birch/dex/type_analysis.h"

#include <array>
#include <cassert>
#include <iostream>

namespace {
birch::dex::DexFile Fixture(bool literals) {
    using namespace birch::dex;
    ClassSpec klass;
    klass.descriptor = "Ldomains/Fixture;";
    MethodSpec method;
    method.name = "run";
    method.return_type = "V";
    method.access_flags = 0x0009U;
    method.parameter_types = {"I", "F", "Ljava/lang/String;"};
    method.body.registers_size = 4U;
    method.body.ins_size = 3U;
    method.body.outs_size = 1U;
    if (literals) {
        method.body.code_units = {0x0012U, 0x0128U, 0x1012U, 0x0128U,
                                  0x2012U, 0x0128U, 0x000eU};
    } else {
        method.body.code_units = {
            0x0128U,                    // @0: undefined local
            0x1001U, 0x0128U,           // @1: int local
            0x2001U, 0x0128U,           // @3: float local
            0x001aU, 0U, 0x0128U,       // @5: String local
            0x3007U, 0x0128U,           // @8: identical String domain
            0x0022U, 0U, 0x0128U,       // @10: uninitialized String
            0x0007U, 0x0128U,           // @13: alias still uninitialized
            0x1070U, 0U, 0U, 0x0128U,   // @15: initialize all aliases
            0x001aU, 0U, 0x0128U,       // @19: identical initialized domain
            0x000eU};
        method.body.references = {
            {std::string("literal"), 6U, false},
            {TypeReference{"Ljava/lang/String;"}, 11U, false},
            {MethodReference{"Ljava/lang/String;", "<init>", "V", {}}, 16U, false},
            {std::string("other"), 20U, false}};
    }
    klass.direct_methods.push_back(std::move(method));
    DexBuilder builder;
    builder.AddClass(std::move(klass));
    return DexFile::Parse(builder.Build());
}

void Check(bool literals) {
    const auto file = Fixture(literals);
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    const auto& method = file.class_data(0U).direct_methods.front();
    const auto ir = birch::dex::BuildMethodIr(birch::dex::DecodeCodeItem(file, method.code_off));
    const birch::guard::detail::CffTypeDomains domains(file, method, ir, {});
    const birch::guard::detail::CffTypeDomains separate(file, method, ir, {}, false);
    const birch::guard::detail::CffTypeDomains projected(file, method, ir, {}, true, true);
    std::vector<birch::dex::BlockId> owners;
    std::vector<std::uint32_t> exits;
    for (const auto& block : ir.blocks()) {
        owners.push_back(projected.Owner(block.id));
        exits.push_back(block.instructions.back().dex_offset);
    }
    const birch::dex::MethodLiveness expanded(ir, owners);
    const auto types = birch::dex::AnalyzeMethodTypes(file, method, ir.code(),
        {exits, {}, nullptr, true});
    for (const auto& left : ir.blocks()) for (const auto& right : ir.blocks()) {
        if (owners[left.id] != owners[right.id]) continue;
        const auto& a = types.exit_register_domains.at(left.instructions.back().dex_offset);
        const auto& b = types.exit_register_domains.at(right.instructions.back().dex_offset);
        for (auto r : expanded.LiveOut(left.id)) assert(a[r] == b[r]);
        for (auto r : expanded.LiveOut(right.id)) assert(a[r] == b[r]);
    }
    for (const auto& block : ir.blocks()) {
        assert(separate.Owner(block.id) == block.id);
        assert(separate.MemberCount(block.id) == 1U);
    }
    const auto owner = [&](std::uint32_t offset) {
        for (const auto& block : ir.blocks())
            if (block.start_offset == offset) return domains.Owner(block.id);
        throw std::runtime_error("missing fixture block");
    };
    if (literals) {
        assert(owner(0U) != owner(2U)); // null-capable vs nonzero scalar
        assert(owner(2U) == owner(4U)); // distinct provenance is not a type
        const std::array<std::uint16_t, 1U> scratch{0U};
        const birch::guard::detail::CffTypeDomains overwritten(file, method, ir, scratch);
        for (const auto& block : ir.blocks()) assert(overwritten.Owner(block.id) == 0U);
    } else {
        for (const auto left : {0U, 1U, 3U})
            for (const auto right : {0U, 1U, 3U, 5U})
                if (left != right) assert(owner(left) != owner(right));
        assert(owner(5U) == owner(8U));
        assert(owner(5U) == owner(15U));
        assert(owner(5U) == owner(19U));
        assert(domains.MemberCount(owner(5U)) >= 4U);
        assert(owner(10U) != owner(13U));
        assert(owner(10U) != owner(5U));
        assert(owner(13U) != owner(5U));
    }
}

void CheckMonitors() {
    birch::dex::DexBuilder builder;
    birch::dex::ClassSpec klass;
    klass.descriptor = "Ldomains/Monitors;";
    birch::dex::MethodSpec method;
    method.name = "run";
    method.return_type = "V";
    method.parameter_types = {"Ljava/lang/Object;"};
    method.access_flags = 0x0009U;
    method.body.registers_size = 1U;
    method.body.ins_size = 1U;
    method.body.code_units = {0x0128U, 0x001dU, 0x0128U, 0x001eU, 0x0128U, 0x000eU};
    klass.direct_methods.push_back(std::move(method));
    builder.AddClass(std::move(klass));
    const auto file = birch::dex::DexFile::Parse(builder.Build());
    birch::dex::VerifyDexOrThrow(file, birch::dex::VerificationLevel::Full);
    const auto& encoded = file.class_data(0U).direct_methods.front();
    const auto ir = birch::dex::BuildMethodIr(birch::dex::DecodeCodeItem(file, encoded.code_off));
    const birch::guard::detail::CffTypeDomains domains(file, encoded, ir, {});
    for (const auto& block : ir.blocks()) {
        assert(domains.Owner(block.id) == block.id);
        assert(domains.MemberCount(block.id) == 1U);
    }
}
} // namespace

int main() {
    Check(false);
    Check(true);
    CheckMonitors();
    std::cout << "Exact CFF domains share; primitive, null and uninitialized domains stay isolated\n";
}
