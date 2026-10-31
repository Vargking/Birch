#include "birch/guard/json.h"

#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <system_error>

namespace birch::guard::json {
namespace {

constexpr std::size_t kMaximumDepth = 128U;

void AppendUtf8(std::string& output, std::uint32_t codepoint, std::size_t offset) {
    if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
        throw ParseError(offset, "invalid Unicode scalar value");
    }
    if (codepoint <= 0x7fU) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (codepoint >> 6U)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else if (codepoint <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (codepoint >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (codepoint >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    }
}

class Parser final {
public:
    explicit Parser(std::string_view source) : source_(source) {}

    Value Run() {
        SkipWhitespace();
        auto result = ParseValue(0U);
        SkipWhitespace();
        if (cursor_ != source_.size()) {
            Fail("trailing data after JSON value");
        }
        return result;
    }

private:
    [[noreturn]] void Fail(std::string message) const {
        throw ParseError(cursor_, std::move(message));
    }

    void SkipWhitespace() {
        while (cursor_ < source_.size()) {
            const auto value = source_[cursor_];
            if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                break;
            }
            ++cursor_;
        }
    }

    bool Consume(char expected) {
        if (cursor_ < source_.size() && source_[cursor_] == expected) {
            ++cursor_;
            return true;
        }
        return false;
    }

    void Expect(char expected) {
        if (!Consume(expected)) {
            Fail(std::string("expected '") + expected + "'");
        }
    }

    bool ConsumeLiteral(std::string_view literal) {
        if (source_.substr(cursor_, literal.size()) != literal) {
            return false;
        }
        cursor_ += literal.size();
        return true;
    }

    Value ParseValue(std::size_t depth) {
        if (depth > kMaximumDepth) {
            Fail("JSON nesting limit exceeded");
        }
        SkipWhitespace();
        if (cursor_ >= source_.size()) {
            Fail("expected JSON value");
        }
        switch (source_[cursor_]) {
            case 'n':
                if (ConsumeLiteral("null")) return Value(Value::Storage(nullptr));
                break;
            case 't':
                if (ConsumeLiteral("true")) return Value(Value::Storage(true));
                break;
            case 'f':
                if (ConsumeLiteral("false")) return Value(Value::Storage(false));
                break;
            case '"': return Value(Value::Storage(ParseString()));
            case '[': return Value(Value::Storage(ParseArray(depth + 1U)));
            case '{': return Value(Value::Storage(ParseObject(depth + 1U)));
            default:
                if (source_[cursor_] == '-' ||
                    (source_[cursor_] >= '0' && source_[cursor_] <= '9')) {
                    return Value(Value::Storage(ParseNumber()));
                }
                break;
        }
        Fail("invalid JSON value");
    }

    std::uint16_t ParseHex16() {
        if (source_.size() - cursor_ < 4U) {
            Fail("truncated Unicode escape");
        }
        std::uint16_t result = 0;
        for (std::size_t i = 0; i < 4U; ++i) {
            const auto value = source_[cursor_++];
            result = static_cast<std::uint16_t>(result << 4U);
            if (value >= '0' && value <= '9') {
                result = static_cast<std::uint16_t>(result | (value - '0'));
            } else if (value >= 'a' && value <= 'f') {
                result = static_cast<std::uint16_t>(result | (value - 'a' + 10));
            } else if (value >= 'A' && value <= 'F') {
                result = static_cast<std::uint16_t>(result | (value - 'A' + 10));
            } else {
                Fail("invalid hexadecimal digit in Unicode escape");
            }
        }
        return result;
    }

    void AppendRawUtf8(std::string& output) {
        const auto start = cursor_;
        const auto first = static_cast<std::uint8_t>(source_[cursor_++]);
        std::size_t length = 0U;
        std::uint32_t codepoint = 0U;
        std::uint32_t minimum = 0U;
        if (first >= 0xc2U && first <= 0xdfU) {
            length = 2U; codepoint = first & 0x1fU; minimum = 0x80U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            length = 3U; codepoint = first & 0x0fU; minimum = 0x800U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            length = 4U; codepoint = first & 0x07U; minimum = 0x10000U;
        } else {
            throw ParseError(start, "invalid UTF-8 leading byte");
        }
        if (source_.size() - start < length) {
            throw ParseError(start, "truncated UTF-8 sequence");
        }
        for (std::size_t i = 1U; i < length; ++i) {
            const auto next = static_cast<std::uint8_t>(source_[cursor_++]);
            if ((next & 0xc0U) != 0x80U) {
                throw ParseError(cursor_ - 1U, "invalid UTF-8 continuation byte");
            }
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if (codepoint < minimum || codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            throw ParseError(start, "invalid UTF-8 scalar value");
        }
        output.append(source_.substr(start, length));
    }

    std::string ParseString() {
        Expect('"');
        std::string result;
        while (cursor_ < source_.size()) {
            const auto value = static_cast<std::uint8_t>(source_[cursor_++]);
            if (value == '"') {
                return result;
            }
            if (value < 0x20U) {
                throw ParseError(cursor_ - 1U, "unescaped control character in string");
            }
            if (value >= 0x80U) {
                --cursor_;
                AppendRawUtf8(result);
                continue;
            }
            if (value != '\\') {
                result.push_back(static_cast<char>(value));
                continue;
            }
            if (cursor_ >= source_.size()) {
                Fail("truncated string escape");
            }
            const auto escape = source_[cursor_++];
            switch (escape) {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u': {
                    const auto escape_offset = cursor_ - 2U;
                    const auto high = ParseHex16();
                    std::uint32_t codepoint = high;
                    if (high >= 0xd800U && high <= 0xdbffU) {
                        if (!Consume('\\') || !Consume('u')) {
                            throw ParseError(escape_offset, "high surrogate without low surrogate");
                        }
                        const auto low = ParseHex16();
                        if (low < 0xdc00U || low > 0xdfffU) {
                            throw ParseError(cursor_ - 4U, "invalid low surrogate");
                        }
                        codepoint = 0x10000U +
                                    ((static_cast<std::uint32_t>(high) - 0xd800U) << 10U) +
                                    (static_cast<std::uint32_t>(low) - 0xdc00U);
                    } else if (high >= 0xdc00U && high <= 0xdfffU) {
                        throw ParseError(escape_offset, "unexpected low surrogate");
                    }
                    AppendUtf8(result, codepoint, escape_offset);
                    break;
                }
                default: throw ParseError(cursor_ - 1U, "invalid string escape");
            }
        }
        Fail("unterminated JSON string");
    }

    double ParseNumber() {
        const auto start = cursor_;
        Consume('-');
        if (Consume('0')) {
            if (cursor_ < source_.size() && source_[cursor_] >= '0' && source_[cursor_] <= '9') {
                Fail("leading zero in JSON number");
            }
        } else {
            if (cursor_ >= source_.size() || source_[cursor_] < '1' || source_[cursor_] > '9') {
                Fail("invalid JSON number");
            }
            while (cursor_ < source_.size() && source_[cursor_] >= '0' &&
                   source_[cursor_] <= '9') ++cursor_;
        }
        if (Consume('.')) {
            if (cursor_ >= source_.size() || source_[cursor_] < '0' || source_[cursor_] > '9') {
                Fail("fraction has no digits");
            }
            while (cursor_ < source_.size() && source_[cursor_] >= '0' &&
                   source_[cursor_] <= '9') ++cursor_;
        }
        if (cursor_ < source_.size() && (source_[cursor_] == 'e' || source_[cursor_] == 'E')) {
            ++cursor_;
            if (cursor_ < source_.size() && (source_[cursor_] == '+' || source_[cursor_] == '-')) {
                ++cursor_;
            }
            if (cursor_ >= source_.size() || source_[cursor_] < '0' || source_[cursor_] > '9') {
                Fail("exponent has no digits");
            }
            while (cursor_ < source_.size() && source_[cursor_] >= '0' &&
                   source_[cursor_] <= '9') ++cursor_;
        }
        double result = 0.0;
        const auto text = source_.substr(start, cursor_ - start);
        const auto conversion = std::from_chars(text.data(), text.data() + text.size(), result,
                                                std::chars_format::general);
        if (conversion.ec != std::errc{} || conversion.ptr != text.data() + text.size() ||
            !std::isfinite(result)) {
            throw ParseError(start, "JSON number is outside supported range");
        }
        return result;
    }

    Value::Array ParseArray(std::size_t depth) {
        Expect('[');
        SkipWhitespace();
        Value::Array result;
        if (Consume(']')) return result;
        while (true) {
            result.push_back(ParseValue(depth));
            SkipWhitespace();
            if (Consume(']')) return result;
            Expect(',');
            SkipWhitespace();
        }
    }

    Value::Object ParseObject(std::size_t depth) {
        Expect('{');
        SkipWhitespace();
        Value::Object result;
        if (Consume('}')) return result;
        while (true) {
            if (cursor_ >= source_.size() || source_[cursor_] != '"') {
                Fail("object key must be a string");
            }
            const auto key_offset = cursor_;
            auto key = ParseString();
            SkipWhitespace();
            Expect(':');
            auto value = ParseValue(depth);
            const auto [unused, inserted] = result.emplace(std::move(key), std::move(value));
            (void)unused;
            if (!inserted) {
                throw ParseError(key_offset, "duplicate JSON object key");
            }
            SkipWhitespace();
            if (Consume('}')) return result;
            Expect(',');
            SkipWhitespace();
        }
    }

    std::string_view source_;
    std::size_t cursor_{};
};

template <typename T>
const T& Get(const Value::Storage& storage, const char* expected) {
    const auto* result = std::get_if<T>(&storage);
    if (result == nullptr) {
        throw std::logic_error(std::string("JSON value is not ") + expected);
    }
    return *result;
}

} // namespace

ParseError::ParseError(std::size_t offset, std::string message)
    : std::runtime_error(std::move(message)), offset_(offset) {}

bool Value::is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(storage_); }
bool Value::is_bool() const noexcept { return std::holds_alternative<bool>(storage_); }
bool Value::is_number() const noexcept { return std::holds_alternative<double>(storage_); }
bool Value::is_string() const noexcept { return std::holds_alternative<std::string>(storage_); }
bool Value::is_array() const noexcept { return std::holds_alternative<Array>(storage_); }
bool Value::is_object() const noexcept { return std::holds_alternative<Object>(storage_); }
bool Value::as_bool() const { return Get<bool>(storage_, "a boolean"); }
double Value::as_number() const { return Get<double>(storage_, "a number"); }
const std::string& Value::as_string() const { return Get<std::string>(storage_, "a string"); }
const Value::Array& Value::as_array() const { return Get<Array>(storage_, "an array"); }
const Value::Object& Value::as_object() const { return Get<Object>(storage_, "an object"); }

Value Parse(std::string_view source) {
    return Parser(source).Run();
}

} // namespace birch::guard::json
