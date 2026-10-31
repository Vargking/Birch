#include "string_dex_interpreter.h"
#include "dex_string_codec.h"
#include "dex_exception.h"

#include "birch/dex/cloner.h"

#include <algorithm>
#include <bit>
#include <stdexcept>
#include <type_traits>

namespace birch::test {

StringDexInterpreter::StringDexInterpreter(const dex::DexFile& file, std::size_t max_steps)
    : file_(file), max_steps_(max_steps) {
    for (std::size_t i = 0; i < file.classes().size(); ++i) {
        const auto& data = file.class_data(i);
        for (const auto* group : {&data.direct_methods, &data.virtual_methods})
            for (const auto& method : *group)
                if (method.code_off) methods_.emplace(method.method_idx, dex::DecodeCodeItem(file, method.code_off));
    }
    for (const auto& [index, code] : methods_) {
        auto& instructions = decoded_[index];
        instructions.resize(code.insns.size());
        for (const auto& ins : code.instructions)
            if (ins.kind != dex::InstructionKind::Payload) instructions.at(ins.offset) = &ins;
    }
}
std::uint32_t StringDexInterpreter::Allocate(Object object) {
    heap_.push_back(std::move(object));
    return static_cast<std::uint32_t>(heap_.size());
}
StringDexInterpreter::Object& StringDexInterpreter::Heap(std::uint32_t handle) {
    if (!handle) throw std::runtime_error("string oracle null object");
    return heap_.at(handle - 1U);
}
std::uint32_t StringDexInterpreter::Intern(std::uint32_t handle) {
    const auto text = Heap(handle).text;
    return interned_.try_emplace(text, handle).first->second;
}
std::u16string StringDexInterpreter::Execute(std::string_view owner, std::string_view name) {
    return Heap(Entry(owner, name)).text;
}
std::uint32_t StringDexInterpreter::ExecuteScalar(std::string_view owner, std::string_view name,
    std::span<const std::uint32_t> arguments, std::string_view prototype) {
    return Entry(owner, name, prototype, arguments);
}
bool StringDexInterpreter::HasStableIdentity(std::string_view owner, std::string_view name) {
    const auto first = Entry(owner, name);
    return first == Entry(owner, name) && Intern(first) == first;
}
std::uint32_t StringDexInterpreter::Entry(std::string_view owner, std::string_view name,
                                         std::string_view prototype,
                                         std::span<const std::uint32_t> arguments) {
    steps_ = 0;
    calls_.clear();
    method_steps_.clear();
    for (std::uint32_t i = 0; i < file_.methods().size(); ++i) {
        const auto& method = file_.methods()[i];
        if (file_.descriptor(method.class_idx) == owner && file_.string(method.name_idx) == name &&
            file_.proto_key(method.proto_idx) == prototype) {
            std::uint32_t result;
            try { result = Call(i, arguments, 0); }
            catch (const DexThrown& thrown) {
                throw std::runtime_error("uncaught DEX " + Heap(thrown.object).type);
            }
            if (prototype == "()Ljava/lang/String;" && Heap(result).type != "Ljava/lang/String;")
                throw std::runtime_error("non-string oracle result");
            return result;
        }
    }
    throw std::runtime_error("string oracle entry not found");
}
void StringDexInterpreter::Initialize(std::string_view owner, std::size_t depth) {
    if (initialized_[std::string(owner)]) return;
    initialized_[std::string(owner)] = 1;
    dex::DexClassCloner cloner(file_);
    for (std::size_t i = 0; i < file_.classes().size(); ++i) {
        if (file_.descriptor(file_.classes()[i].class_idx) != owner) continue;
        const auto klass = cloner.Clone(i);
        for (const auto& field : klass.static_fields) {
            for (std::uint32_t f = 0; f < file_.fields().size(); ++f) {
                const auto& id = file_.fields()[f];
                if (file_.descriptor(id.class_idx) != owner || file_.string(id.name_idx) != field.name) continue;
                std::uint32_t value = 0;
                if (field.static_value) {
                    value = std::visit([&](const auto& item) -> std::uint32_t {
                        using T = std::decay_t<decltype(item)>;
                        if constexpr (std::is_integral_v<T>) return static_cast<std::uint32_t>(item);
                        else if constexpr (std::is_same_v<T, float>) return std::bit_cast<std::uint32_t>(item);
                        else if constexpr (std::is_same_v<T, dex::NullEncodedValue>) return 0;
                        else if constexpr (std::is_same_v<T, dex::StringReference>)
                            return Intern(Allocate({"Ljava/lang/String;", {}, Utf16(item.value)}));
                        else throw std::runtime_error("string oracle unsupported static value");
                    }, field.static_value->value);
                }
                fields_[f] = value;
            }
        }
        for (const auto& method : file_.class_data(i).direct_methods)
            if (file_.string(file_.methods().at(method.method_idx).name_idx) == "<clinit>")
                Call(method.method_idx, {}, depth + 1U);
    }
    initialized_[std::string(owner)] = 2;
}
std::uint32_t StringDexInterpreter::Call(std::uint32_t index, std::span<const std::uint32_t> args, std::size_t depth) {
    if (depth > 256U) throw std::runtime_error("string oracle call depth exceeded");
    const auto& id = file_.methods().at(index);
    const auto owner = file_.descriptor(id.class_idx);
    const auto name = file_.string(id.name_idx);
    const auto proto = file_.proto_key(id.proto_idx);
    if (methods_.contains(index)) {
        Initialize(owner, depth);
        ++calls_[index];
        try { return Run(methods_.at(index), args, depth, index); }
        catch (const std::exception& error) {
            throw std::runtime_error(owner + "->" + name + proto + ": " + error.what());
        }
    }
    if (owner == "Ljava/lang/String;" && name == "<init>" && proto == "([C)V" && args.size() == 2U) {
        const auto chars = Heap(args[1]).elements;
        auto& object = Heap(args[0]);
        object.text.clear();
        for (const auto c : chars) object.text.push_back(static_cast<char16_t>(c));
        return 0;
    }
    if (owner == "Ljava/lang/String;" && name == "concat" && proto == "(Ljava/lang/String;)Ljava/lang/String;" && args.size() == 2U) {
        const auto text = Heap(args[0]).text + Heap(args[1]).text;
        return Allocate({owner, {}, text});
    }
    if (owner == "Ljava/lang/System;" && name == "identityHashCode" && proto == "(Ljava/lang/Object;)I" && args.size() == 1U)
        return args[0] == 0U ? 0U : args[0] * 0x9e3779b9U;
    if (owner == "Ljava/lang/System;" && name == "arraycopy" &&
        proto == "(Ljava/lang/Object;ILjava/lang/Object;II)V" && args.size() == 5U) {
        const auto& source = Heap(args[0]);
        auto& target = Heap(args[2]);
        if (source.type.size() != 2U || source.type.front() != '[' ||
            source.type != target.type ||
            std::string_view("ZBCSIF").find(source.type.back()) == std::string_view::npos)
            throw std::runtime_error("string oracle unsupported arraycopy types");
        if (std::bit_cast<std::int32_t>(args[1]) < 0 ||
            std::bit_cast<std::int32_t>(args[3]) < 0 ||
            std::bit_cast<std::int32_t>(args[4]) < 0 ||
            args[1] > source.elements.size() || args[3] > target.elements.size() ||
            args[4] > source.elements.size() - args[1] ||
            args[4] > target.elements.size() - args[3])
            throw std::runtime_error("string oracle arraycopy out of bounds");
        // Java defines overlapping copies as if a temporary array were used.
        const std::vector<std::uint32_t> copy(source.elements.begin() + args[1],
            source.elements.begin() + args[1] + args[4]);
        std::copy(copy.begin(), copy.end(), target.elements.begin() + args[3]);
        return 0;
    }
    if (owner == "Ljava/lang/String;" && name == "intern" && proto == "()Ljava/lang/String;" && args.size() == 1U)
        return Intern(args[0]);
    if (owner == "Ljava/lang/String;" && name == "length" && proto == "()I" && args.size() == 1U)
        return static_cast<std::uint32_t>(Heap(args[0]).text.size());
    if (owner == "Ljava/lang/Float;" && name == "intBitsToFloat" && proto == "(I)F" && args.size() == 1U)
        return args[0]; // register representation is the unchanged IEEE-754 bits
    if (owner == "Ljava/lang/Float;" && name == "floatToRawIntBits" && proto == "(F)I" && args.size() == 1U)
        return args[0];
    if (owner == "Ljava/lang/Class;" && name == "getClassLoader" && proto == "()Ljava/lang/ClassLoader;" && args.size() == 1U) {
        (void)Heap(args[0]);
        if (!class_loader_) class_loader_ = Allocate({"Ljava/lang/ClassLoader;", {}, {}});
        return *class_loader_;
    }
    throw std::runtime_error("string oracle unsupported call " + owner + "->" + name + proto);
}

} // namespace birch::test
