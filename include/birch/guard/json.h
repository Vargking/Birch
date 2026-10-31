#pragma once

#include <cstddef>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace birch::guard::json {

class ParseError final : public std::runtime_error {
public:
    ParseError(std::size_t offset, std::string message);
    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

private:
    std::size_t offset_{};
};

class Value final {
public:
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value, std::less<>>;
    using Storage = std::variant<std::nullptr_t, bool, double, std::string, Array, Object>;

    Value() : storage_(nullptr) {}
    explicit Value(Storage storage) : storage_(std::move(storage)) {}

    [[nodiscard]] bool is_null() const noexcept;
    [[nodiscard]] bool is_bool() const noexcept;
    [[nodiscard]] bool is_number() const noexcept;
    [[nodiscard]] bool is_string() const noexcept;
    [[nodiscard]] bool is_array() const noexcept;
    [[nodiscard]] bool is_object() const noexcept;
    [[nodiscard]] bool as_bool() const;
    [[nodiscard]] double as_number() const;
    [[nodiscard]] const std::string& as_string() const;
    [[nodiscard]] const Array& as_array() const;
    [[nodiscard]] const Object& as_object() const;

private:
    Storage storage_;
};

Value Parse(std::string_view source);

} // namespace birch::guard::json
