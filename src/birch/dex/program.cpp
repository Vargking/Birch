#include "birch/dex/program.h"

#include <map>
#include <sstream>
#include <stdexcept>

namespace birch::dex {

DexProgram DexProgram::Parse(std::vector<DexInput> inputs) {
    if (inputs.empty()) {
        throw std::invalid_argument("DEX program requires at least one input");
    }
    DexProgram result;
    std::map<std::string, std::string> owners;
    for (auto& input : inputs) {
        if (input.name.empty()) {
            throw std::invalid_argument("DEX input name must not be empty");
        }
        const auto container = DexContainer::Parse(input.bytes);
        for (std::size_t entry_index = 0U; entry_index < container.size(); ++entry_index) {
            auto file = container.dex(entry_index);
            std::string unit_name = input.name;
            if (container.size() > 1U) {
                std::ostringstream suffix;
                suffix << "@0x" << std::hex << file.header().header_offset;
                unit_name += suffix.str();
            }
            for (const auto& definition : file.classes()) {
                const auto descriptor = file.descriptor(definition.class_idx);
                const auto [it, inserted] = owners.emplace(descriptor, unit_name);
                if (!inserted) {
                    throw std::invalid_argument("duplicate class " + descriptor + " in " +
                                                it->second + " and " + unit_name);
                }
            }
            result.units_.push_back({std::move(unit_name), std::move(file)});
        }
    }
    return result;
}

const DexFile& DexProgram::dex(std::size_t index) const {
    if (index >= units_.size()) {
        throw std::out_of_range("DEX index out of range");
    }
    return units_[index].file;
}

std::string_view DexProgram::dex_name(std::size_t index) const {
    if (index >= units_.size()) {
        throw std::out_of_range("DEX index out of range");
    }
    return units_[index].name;
}

std::vector<ClassHandle> DexProgram::classes() const {
    std::vector<ClassHandle> result;
    for (std::size_t dex_index = 0; dex_index < units_.size(); ++dex_index) {
        for (std::size_t class_index = 0;
             class_index < units_[dex_index].file.classes().size(); ++class_index) {
            result.push_back({dex_index, class_index});
        }
    }
    return result;
}

std::vector<ClassHandle> DexProgram::FindClassesWithPrefix(
    std::string_view descriptor_prefix) const {
    std::vector<ClassHandle> result;
    for (const auto handle : classes()) {
        const auto descriptor = class_descriptor(handle);
        if (descriptor.starts_with(descriptor_prefix)) {
            result.push_back(handle);
        }
    }
    return result;
}

std::string DexProgram::class_descriptor(ClassHandle handle) const {
    const auto& file = dex(handle.dex_index);
    if (handle.class_index >= file.classes().size()) {
        throw std::out_of_range("class index out of range");
    }
    return file.descriptor(file.classes()[handle.class_index].class_idx);
}

} // namespace birch::dex
