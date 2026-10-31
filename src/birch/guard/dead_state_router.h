#pragma once

#include "dead_state_emitter.h"

#include <span>
#include <vector>

namespace birch::guard::detail {

// Dead edges never re-enter a business dispatcher: ART must not merge their
// local-register types back into live code. Each shard owns its key, decoder
// and small switch instead of converging on a method-wide decoder/switch.
class DeadStateRouter final {
public:
    struct Shard {
        CffAssembler::Label dispatcher;
        std::vector<std::uint32_t> keys;
        std::vector<CffAssembler::Label> targets;
    };

    DeadStateRouter(CffAssembler& assembler, std::uint16_t state_register,
                    std::span<const std::uint32_t> states,
                    std::span<const CffAssembler::Label> targets,
                    bool packed, std::uint64_t seed);

    void EmitSelector(std::uint16_t scratch_register);
    void EmitEdge(std::uint32_t current, std::size_t target, std::uint64_t salt);
    void EmitEntry(std::size_t target);
    void EmitFallback(std::size_t shard, std::uint64_t salt);
    void FlushLocalDecoders();
    void BindShard(std::size_t shard);
    [[nodiscard]] const std::vector<Shard>& shards() const noexcept { return shards_; }
    [[nodiscard]] bool packed() const noexcept { return packed_; }

private:
    CffAssembler* assembler_;
    std::uint16_t state_register_;
    std::uint32_t first_{};
    unsigned shift_{7U};
    bool packed_;
    bool local_decoders_;
    std::vector<Shard> shards_;
    std::vector<DeadStateEmitter> edges_;
    std::vector<std::size_t> shard_by_state_;
    std::vector<std::uint32_t> states_;
};

} // namespace birch::guard::detail
