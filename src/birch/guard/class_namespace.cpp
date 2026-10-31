#include "class_namespace.h"

#include <string_view>

namespace birch::guard::detail {

void ClassNamespace::Reserve(const dex::DexFile& file) {
    for (std::size_t index = 0U; index < file.types().size(); ++index) {
        const auto descriptor = file.descriptor(static_cast<std::uint32_t>(index));
        auto element = std::string_view(descriptor);
        while (element.starts_with('[')) element.remove_prefix(1U);
        if (element.starts_with('L')) names_.emplace(element);
    }
}

} // namespace birch::guard::detail
