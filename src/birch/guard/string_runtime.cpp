#include "birch/guard/string_runtime.h"

#include "birch/utils/hash.h"

#include <iomanip>
#include <sstream>

namespace birch::guard {

std::string RuntimeStringMethodName(std::string_view value, std::uint64_t seed) {
    std::ostringstream stream;
    stream << kStringHelperMethodPrefix << std::hex << std::setfill('0')
           << std::setw(16) << utils::StableHash64(value, seed)
           << std::setw(16) << utils::StableHash64(value, seed ^ 0x9e3779b97f4a7c15ULL);
    return stream.str();
}

} // namespace birch::guard
