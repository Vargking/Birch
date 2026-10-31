#pragma once

#include "cff_assembler.h"

#include <cstdint>

namespace birch::guard::detail {

// Encodes edges within one independently keyed dead-graph shard.
class DeadStateEmitter final {
  public:
    DeadStateEmitter(CffAssembler &assembler, std::uint16_t state_register,
                     CffAssembler::Label dispatcher, std::uint64_t seed, bool local_decoders);

    void Emit(std::uint32_t current, std::uint32_t target, std::uint64_t salt);
    void EmitEntry(std::uint32_t target);
    void BindDecoder(bool fallthrough_to_dispatcher = false);

  private:
    CffAssembler *assembler_;
    std::uint16_t state_register_;
    CffAssembler::Label dispatcher_;
    CffAssembler::Label decoder_;
    std::uint8_t xor_key_;
    bool decoder_used_{};
    bool local_decoders_{};
};

} // namespace birch::guard::detail
