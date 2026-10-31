#include "dead_state_emitter.h"

#include <bit>
#include <limits>

namespace birch::guard::detail {

DeadStateEmitter::DeadStateEmitter(CffAssembler &assembler, std::uint16_t state_register,
                                   CffAssembler::Label dispatcher, std::uint64_t seed,
                                   bool local_decoders)
    : assembler_(&assembler), state_register_(state_register), dispatcher_(dispatcher),
      decoder_(assembler.NewLabel()), xor_key_(static_cast<std::uint8_t>((seed & 0x7fU) | 1U)),
      local_decoders_(local_decoders) {}

void DeadStateEmitter::Emit(std::uint32_t current, std::uint32_t target, std::uint64_t salt) {
    // DEX integer arithmetic wraps. Bit-casting the unsigned difference
    // avoids signed overflow and implementation-defined narrowing.
    const auto delta = std::bit_cast<std::int32_t>((target ^ xor_key_) - current);
    if (state_register_ <= 15U && delta >= std::numeric_limits<std::int16_t>::min() &&
        delta <= std::numeric_limits<std::int16_t>::max()) {
        decoder_used_ = true;
        assembler_->Emit(
            {static_cast<std::uint16_t>(0xd0U | (state_register_ << 8U) | (state_register_ << 12U)),
             static_cast<std::uint16_t>(delta)});
        if (local_decoders_)
            assembler_->EmitGoto8(decoder_);
        else
            assembler_->EmitGoto16(decoder_);
        return;
    }
    if (local_decoders_ && state_register_ > 15U) {
        if (delta >= std::numeric_limits<std::int8_t>::min() &&
            delta <= std::numeric_limits<std::int8_t>::max()) {
            decoder_used_ = true;
            assembler_->Emit({static_cast<std::uint16_t>(0xd8U | (state_register_ << 8U)),
                static_cast<std::uint16_t>(state_register_ |
                    (static_cast<std::uint16_t>(static_cast<std::uint8_t>(delta)) << 8U))});
            assembler_->EmitGoto8(decoder_);
        } else {
            // 22s cannot address v16..v255. Keep the same keyed local
            // decoder, using an absolute encoded token where 22b cannot
            // represent the relative delta. Do not duplicate full encoders
            // at all 1024 edges just because a method has many locals.
            EmitEntry(target);
        }
        return;
    }
    if (!assembler_->EmitRelativeEncodedState(state_register_, current, target, salt)) {
        assembler_->EmitEncodedState(state_register_, target, salt);
    }
    assembler_->EmitGoto16(dispatcher_);
}

void DeadStateEmitter::BindDecoder(bool fallthrough_to_dispatcher) {
    assembler_->Bind(decoder_);
    if (decoder_used_) {
        assembler_->Emit({static_cast<std::uint16_t>(0xdfU | (state_register_ << 8U)),
                          static_cast<std::uint16_t>(state_register_ | (xor_key_ << 8U))});
        if (!fallthrough_to_dispatcher) assembler_->EmitGoto16(dispatcher_);
    }
    decoder_ = assembler_->NewLabel();
    decoder_used_ = false;
}

void DeadStateEmitter::EmitEntry(std::uint32_t target) {
    // Unknown/invalid predecessor values must not enter a relative edge.
    // Each shard's keyed decode island normalizes an absolute entry instead.
    assembler_->EmitConst32(state_register_, target ^ xor_key_);
    decoder_used_ = true;
    if (local_decoders_)
        assembler_->EmitGoto8(decoder_);
    else
        assembler_->EmitGoto16(decoder_);
}

} // namespace birch::guard::detail
