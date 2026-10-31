#include "birch/dex/dex_file.h"

#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    const std::vector<std::uint8_t> invalid{'d', 'e', 'x', '\n', '0', '3', '5', 0};
    bool rejected = false;
    try {
        (void)birch::dex::DexFile::Parse(invalid);
    } catch (const birch::dex::DexParseError&) {
        rejected = true;
    }
    assert(rejected);

    // Checksum verification is intentionally independent from parsing so callers
    // can reject stale or tampered DEX input before a transformation pass.
    const std::vector<std::uint8_t> too_small(0x70U, 0U);
    rejected = false;
    try {
        (void)birch::dex::DexFile::Parse(too_small);
    } catch (const birch::dex::DexParseError&) {
        rejected = true;
    }
    assert(rejected);
    return 0;
}
