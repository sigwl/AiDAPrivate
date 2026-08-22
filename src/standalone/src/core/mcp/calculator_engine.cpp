#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "calculator_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;

    namespace
    {
        constexpr std::size_t k_max_expression_bytes = 1024 * 1024;
        constexpr std::size_t k_max_blob_bytes = 1024 * 1024;
        constexpr std::size_t k_max_integer_bytes = CALC_MAX_BITS / 8;
        constexpr std::size_t k_internal_bits = CALC_MAX_BITS + 1;

        class calc_error final : public std::runtime_error
        {
        public:
            calc_error(std::string code, std::string message)
                : std::runtime_error(std::move(message)), code_(std::move(code))
            {
            }

            const std::string& code() const noexcept
            {
                return code_;
            }

        private:
            std::string code_;
        };

        [[noreturn]] void fail(const char* code, const std::string& message)
        {
            throw calc_error(code, message);
        }

        class calculator_interrupt_t
        {
        public:
            explicit calculator_interrupt_t(const workspace_request_context_t& context)
                : context_(context)
            {
            }

            void check_now() const
            {
                if (context_.cancellation_requested())
                    fail("CANCELLED", "calculator request cancelled");
                if (context_.deadline_ms != 0 && static_cast<std::uint64_t>(::GetTickCount64()) >= context_.deadline_ms)
                    fail("DEADLINE_EXCEEDED", "calculator request deadline exceeded");
            }

            void checkpoint()
            {
                if ((++checkpoint_count_ & 0x3FU) == 0)
                    check_now();
            }

        private:
            const workspace_request_context_t& context_;
            std::size_t checkpoint_count_ = 0;
        };

        thread_local calculator_interrupt_t* g_calculator_interrupt = nullptr;

        class interrupt_scope_t
        {
        public:
            explicit interrupt_scope_t(calculator_interrupt_t& interrupt)
                : previous_(g_calculator_interrupt)
            {
                g_calculator_interrupt = &interrupt;
            }

            ~interrupt_scope_t()
            {
                g_calculator_interrupt = previous_;
            }

            interrupt_scope_t(const interrupt_scope_t&) = delete;
            interrupt_scope_t& operator=(const interrupt_scope_t&) = delete;

        private:
            calculator_interrupt_t* previous_;
        };

        void checkpoint()
        {
            if (g_calculator_interrupt)
                g_calculator_interrupt->checkpoint();
        }

        std::string lower_ascii(std::string value)
        {
            for (char& c : value)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return value;
        }

        bool valid_identifier(const std::string& value)
        {
            if (value.empty() || !(std::isalpha(static_cast<unsigned char>(value.front())) || value.front() == '_'))
                return false;
            for (char c : value) {
                if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
                    return false;
            }
            return true;
        }

        class bigint
        {
        public:
            bigint() = default;

            explicit bigint(std::uint64_t value)
            {
                if (value != 0) {
                    limbs_.push_back(static_cast<std::uint32_t>(value));
                    const std::uint32_t high = static_cast<std::uint32_t>(value >> 32U);
                    if (high != 0)
                        limbs_.push_back(high);
                }
            }

            static bigint one()
            {
                return bigint(1);
            }

            bool is_zero() const noexcept
            {
                return limbs_.empty();
            }

            bool is_negative() const noexcept
            {
                return negative_;
            }

            std::size_t bit_count() const noexcept
            {
                if (limbs_.empty())
                    return 0;
                std::uint32_t high = limbs_.back();
                std::size_t result = (limbs_.size() - 1) * 32;
                while (high != 0) {
                    ++result;
                    high >>= 1U;
                }
                return result;
            }

            int compare_abs(const bigint& other) const noexcept
            {
                if (limbs_.size() != other.limbs_.size())
                    return limbs_.size() < other.limbs_.size() ? -1 : 1;
                for (std::size_t i = limbs_.size(); i > 0; --i) {
                    if (limbs_[i - 1] != other.limbs_[i - 1])
                        return limbs_[i - 1] < other.limbs_[i - 1] ? -1 : 1;
                }
                return 0;
            }

            int compare(const bigint& other) const noexcept
            {
                if (negative_ != other.negative_)
                    return negative_ ? -1 : 1;
                const int comparison = compare_abs(other);
                return negative_ ? -comparison : comparison;
            }

            bigint negated() const
            {
                bigint result = *this;
                if (!result.is_zero())
                    result.negative_ = !result.negative_;
                return result;
            }

            bigint absolute() const
            {
                bigint result = *this;
                result.negative_ = false;
                return result;
            }

            bigint added(const bigint& other) const
            {
                if (negative_ == other.negative_) {
                    bigint result = add_abs(*this, other);
                    result.negative_ = negative_;
                    return result;
                }
                const int comparison = compare_abs(other);
                if (comparison == 0)
                    return bigint();
                if (comparison > 0) {
                    bigint result = subtract_abs(*this, other);
                    result.negative_ = negative_;
                    return result;
                }
                bigint result = subtract_abs(other, *this);
                result.negative_ = other.negative_;
                return result;
            }

            bigint subtracted(const bigint& other) const
            {
                return added(other.negated());
            }

            bigint multiplied(const bigint& other) const
            {
                if (is_zero() || other.is_zero())
                    return bigint();
                bigint result;
                result.limbs_.assign(limbs_.size() + other.limbs_.size() + 1, 0);
                for (std::size_t i = 0; i < limbs_.size(); ++i) {
                    checkpoint();
                    std::uint64_t carry = 0;
                    for (std::size_t j = 0; j < other.limbs_.size(); ++j) {
                        const std::uint64_t current = static_cast<std::uint64_t>(result.limbs_[i + j]) +
                            static_cast<std::uint64_t>(limbs_[i]) * other.limbs_[j] + carry;
                        result.limbs_[i + j] = static_cast<std::uint32_t>(current);
                        carry = current >> 32U;
                    }
                    std::size_t index = i + other.limbs_.size();
                    while (carry != 0) {
                        const std::uint64_t current = static_cast<std::uint64_t>(result.limbs_[index]) + carry;
                        result.limbs_[index] = static_cast<std::uint32_t>(current);
                        carry = current >> 32U;
                        ++index;
                    }
                }
                result.negative_ = negative_ != other.negative_;
                result.normalize();
                return result;
            }

            bigint shifted_left(std::size_t bits) const
            {
                if (is_zero() || bits == 0)
                    return *this;
                bigint result = shifted_left_abs(bits);
                result.negative_ = negative_;
                return result;
            }

            bigint shifted_right_arithmetic(std::size_t bits) const
            {
                if (is_zero() || bits == 0)
                    return *this;
                bigint magnitude = shifted_right_abs(bits);
                if (!negative_)
                    return magnitude;
                if (has_low_bits(bits))
                    magnitude = magnitude.added(one());
                if (!magnitude.is_zero())
                    magnitude.negative_ = true;
                return magnitude;
            }

            bigint low_bits(std::size_t bits) const
            {
                if (bits == 0 || limbs_.empty())
                    return bigint();
                bigint result;
                const std::size_t words = (bits + 31) / 32;
                result.limbs_.assign(limbs_.begin(), limbs_.begin() + std::min(words, limbs_.size()));
                const std::size_t remainder = bits % 32;
                if (remainder != 0 && !result.limbs_.empty())
                    result.limbs_.back() &= static_cast<std::uint32_t>((std::uint64_t(1) << remainder) - 1U);
                result.normalize();
                return result;
            }

            bigint unsigned_mod(std::size_t bits) const
            {
                if (bits == 0)
                    return bigint();
                bigint result = absolute().low_bits(bits);
                if (!negative_ || result.is_zero())
                    return result;
                return pow2(bits).subtracted(result);
            }

            static bigint from_twos_complement(const bigint& raw, std::size_t bits)
            {
                if (bits == 0)
                    return bigint();
                bigint normalized = raw.unsigned_mod(bits);
                const bigint sign = pow2(bits - 1);
                if (normalized.compare_abs(sign) < 0)
                    return normalized;
                return normalized.subtracted(pow2(bits));
            }

            static bigint pow2(std::size_t bits)
            {
                bigint result;
                result.limbs_.assign(bits / 32 + 1, 0);
                result.limbs_[bits / 32] = static_cast<std::uint32_t>(std::uint64_t(1) << (bits % 32));
                return result;
            }

            std::size_t twos_width() const noexcept
            {
                if (!negative_)
                    return bit_count() + 1;
                const bigint adjusted = absolute().subtracted(one());
                return adjusted.bit_count() + 1;
            }

            static std::pair<bigint, bigint> divide_with_remainder(const bigint& dividend, const bigint& divisor)
            {
                if (divisor.is_zero())
                    fail("DOMAIN_ERROR", "division by zero");
                auto result = divide_abs_with_remainder(dividend.absolute(), divisor.absolute());
                if (!result.first.is_zero())
                    result.first.negative_ = dividend.negative_ != divisor.negative_;
                if (!result.second.is_zero())
                    result.second.negative_ = dividend.negative_;
                return result;
            }

            std::uint64_t to_u64_checked() const
            {
                if (negative_ || bit_count() > 64)
                    fail("RANGE_ERROR", "integer does not fit in 64 bits");
                std::uint64_t result = 0;
                if (!limbs_.empty())
                    result = limbs_[0];
                if (limbs_.size() > 1)
                    result |= static_cast<std::uint64_t>(limbs_[1]) << 32U;
                return result;
            }

            std::string to_decimal() const
            {
                if (is_zero())
                    return "0";
                bigint value = absolute();
                std::string output;
                while (!value.is_zero()) {
                    checkpoint();
                    const std::uint32_t remainder = value.divide_small(10);
                    output.push_back(static_cast<char>('0' + remainder));
                }
                if (negative_)
                    output.push_back('-');
                std::reverse(output.begin(), output.end());
                return output;
            }

            std::string to_hexadecimal() const
            {
                if (is_zero())
                    return "0x0";
                static constexpr char digits[] = "0123456789ABCDEF";
                std::string output;
                if (negative_)
                    output.push_back('-');
                output.append("0x");
                std::uint32_t high = limbs_.back();
                bool started = false;
                for (int shift = 28; shift >= 0; shift -= 4) {
                    const char digit = digits[(high >> shift) & 0xFU];
                    if (digit != '0' || started) {
                        output.push_back(digit);
                        started = true;
                    }
                }
                for (std::size_t i = limbs_.size() - 1; i > 0; --i) {
                    const std::uint32_t limb = limbs_[i - 1];
                    for (int shift = 28; shift >= 0; shift -= 4)
                        output.push_back(digits[(limb >> shift) & 0xFU]);
                }
                return output;
            }

            std::string to_binary() const
            {
                if (is_zero())
                    return "0b0";
                std::string output;
                if (negative_)
                    output.push_back('-');
                output.append("0b");
                bool started = false;
                for (std::size_t i = limbs_.size(); i > 0; --i) {
                    const std::uint32_t limb = limbs_[i - 1];
                    for (int bit = 31; bit >= 0; --bit) {
                        const bool set = ((limb >> bit) & 1U) != 0;
                        if (set || started) {
                            output.push_back(set ? '1' : '0');
                            started = true;
                        }
                    }
                }
                return output;
            }

            std::string to_octal() const
            {
                if (is_zero())
                    return "0o0";
                bigint value = absolute();
                std::string digits;
                while (!value.is_zero()) {
                    checkpoint();
                    const std::uint32_t remainder = value.divide_small(8);
                    digits.push_back(static_cast<char>('0' + remainder));
                }
                std::reverse(digits.begin(), digits.end());
                return std::string(negative_ ? "-0o" : "0o") + digits;
            }

            void multiply_small(std::uint32_t value)
            {
                if (value == 0 || is_zero()) {
                    limbs_.clear();
                    negative_ = false;
                    return;
                }
                std::uint64_t carry = 0;
                for (std::uint32_t& limb : limbs_) {
                    const std::uint64_t current = static_cast<std::uint64_t>(limb) * value + carry;
                    limb = static_cast<std::uint32_t>(current);
                    carry = current >> 32U;
                }
                if (carry != 0)
                    limbs_.push_back(static_cast<std::uint32_t>(carry));
            }

            void add_small(std::uint32_t value)
            {
                if (value == 0)
                    return;
                if (limbs_.empty()) {
                    limbs_.push_back(value);
                    return;
                }
                std::uint64_t carry = value;
                for (std::size_t i = 0; i < limbs_.size() && carry != 0; ++i) {
                    const std::uint64_t current = static_cast<std::uint64_t>(limbs_[i]) + carry;
                    limbs_[i] = static_cast<std::uint32_t>(current);
                    carry = current >> 32U;
                }
                if (carry != 0)
                    limbs_.push_back(static_cast<std::uint32_t>(carry));
            }

        private:
            std::vector<std::uint32_t> limbs_;
            bool negative_ = false;

            void normalize()
            {
                while (!limbs_.empty() && limbs_.back() == 0)
                    limbs_.pop_back();
                if (limbs_.empty())
                    negative_ = false;
            }

            static bigint add_abs(const bigint& lhs, const bigint& rhs)
            {
                bigint result;
                const std::size_t count = std::max(lhs.limbs_.size(), rhs.limbs_.size());
                result.limbs_.resize(count);
                std::uint64_t carry = 0;
                for (std::size_t i = 0; i < count; ++i) {
                    const std::uint64_t current =
                        (i < lhs.limbs_.size() ? lhs.limbs_[i] : 0U) +
                        (i < rhs.limbs_.size() ? rhs.limbs_[i] : 0U) + carry;
                    result.limbs_[i] = static_cast<std::uint32_t>(current);
                    carry = current >> 32U;
                }
                if (carry != 0)
                    result.limbs_.push_back(static_cast<std::uint32_t>(carry));
                return result;
            }

            static bigint subtract_abs(const bigint& lhs, const bigint& rhs)
            {
                bigint result;
                result.limbs_.resize(lhs.limbs_.size());
                std::uint64_t borrow = 0;
                for (std::size_t i = 0; i < lhs.limbs_.size(); ++i) {
                    const std::uint64_t left = lhs.limbs_[i];
                    const std::uint64_t right = (i < rhs.limbs_.size() ? rhs.limbs_[i] : 0U) + borrow;
                    if (left < right) {
                        result.limbs_[i] = static_cast<std::uint32_t>((std::uint64_t(1) << 32U) + left - right);
                        borrow = 1;
                    } else {
                        result.limbs_[i] = static_cast<std::uint32_t>(left - right);
                        borrow = 0;
                    }
                }
                result.normalize();
                return result;
            }

            bigint shifted_left_abs(std::size_t bits) const
            {
                bigint result;
                const std::size_t words = bits / 32;
                const std::size_t remainder = bits % 32;
                result.limbs_.assign(limbs_.size() + words + 1, 0);
                std::uint64_t carry = 0;
                for (std::size_t i = 0; i < limbs_.size(); ++i) {
                    const std::uint64_t current = (static_cast<std::uint64_t>(limbs_[i]) << remainder) | carry;
                    result.limbs_[i + words] = static_cast<std::uint32_t>(current);
                    carry = current >> 32U;
                }
                result.limbs_[limbs_.size() + words] = static_cast<std::uint32_t>(carry);
                result.normalize();
                return result;
            }

            bigint shifted_right_abs(std::size_t bits) const
            {
                const std::size_t words = bits / 32;
                const std::size_t remainder = bits % 32;
                if (words >= limbs_.size())
                    return bigint();
                bigint result;
                result.limbs_.resize(limbs_.size() - words);
                if (remainder == 0) {
                    std::copy(limbs_.begin() + words, limbs_.end(), result.limbs_.begin());
                } else {
                    std::uint32_t carry = 0;
                    for (std::size_t i = result.limbs_.size(); i > 0; --i) {
                        const std::uint32_t current = limbs_[words + i - 1];
                        result.limbs_[i - 1] = (current >> remainder) | (carry << (32U - remainder));
                        carry = current & static_cast<std::uint32_t>((std::uint64_t(1) << remainder) - 1U);
                    }
                }
                result.normalize();
                return result;
            }

            bool has_low_bits(std::size_t bits) const noexcept
            {
                if (bits == 0)
                    return false;
                const std::size_t words = bits / 32;
                const std::size_t remainder = bits % 32;
                for (std::size_t i = 0; i < std::min(words, limbs_.size()); ++i) {
                    if (limbs_[i] != 0)
                        return true;
                }
                if (remainder != 0 && words < limbs_.size())
                    return (limbs_[words] & static_cast<std::uint32_t>((std::uint64_t(1) << remainder) - 1U)) != 0;
                return false;
            }

            std::uint32_t divide_small(std::uint32_t divisor)
            {
                std::uint64_t remainder = 0;
                for (std::size_t i = limbs_.size(); i > 0; --i) {
                    const std::uint64_t current = (remainder << 32U) | limbs_[i - 1];
                    limbs_[i - 1] = static_cast<std::uint32_t>(current / divisor);
                    remainder = current % divisor;
                }
                normalize();
                return static_cast<std::uint32_t>(remainder);
            }

            static std::pair<bigint, bigint> divide_abs_with_remainder(const bigint& dividend, const bigint& divisor)
            {
                if (dividend.compare_abs(divisor) < 0)
                    return {bigint(), dividend};
                if (divisor.limbs_.size() == 1) {
                    bigint quotient = dividend;
                    const std::uint32_t remainder = quotient.divide_small(divisor.limbs_.front());
                    return {quotient, bigint(remainder)};
                }

                std::uint32_t top = divisor.limbs_.back();
                std::size_t shift = 0;
                while ((top & 0x80000000U) == 0) {
                    ++shift;
                    top <<= 1U;
                }
                bigint normalized_divisor = divisor.shifted_left_abs(shift);
                bigint normalized_dividend = dividend.shifted_left_abs(shift);
                normalized_dividend.limbs_.push_back(0);
                const std::size_t n = normalized_divisor.limbs_.size();
                const std::size_t m = normalized_dividend.limbs_.size() - n - 1;
                bigint quotient;
                quotient.limbs_.assign(m + 1, 0);
                constexpr std::uint64_t base = std::uint64_t(1) << 32U;

                for (std::size_t offset = m + 1; offset > 0; --offset) {
                    checkpoint();
                    const std::size_t j = offset - 1;
                    const std::uint64_t numerator =
                        (static_cast<std::uint64_t>(normalized_dividend.limbs_[j + n]) << 32U) |
                        normalized_dividend.limbs_[j + n - 1];
                    std::uint64_t estimate = numerator / normalized_divisor.limbs_[n - 1];
                    std::uint64_t remainder = numerator % normalized_divisor.limbs_[n - 1];
                    while (estimate == base ||
                           estimate * normalized_divisor.limbs_[n - 2] >
                               (remainder << 32U) + normalized_dividend.limbs_[j + n - 2]) {
                        --estimate;
                        remainder += normalized_divisor.limbs_[n - 1];
                        if (remainder >= base)
                            break;
                    }

                    std::uint64_t carry = 0;
                    std::uint64_t borrow = 0;
                    for (std::size_t i = 0; i < n; ++i) {
                        const std::uint64_t product = estimate * normalized_divisor.limbs_[i] + carry;
                        carry = product >> 32U;
                        const std::uint64_t subtract = static_cast<std::uint32_t>(product) + borrow;
                        const std::uint64_t current = normalized_dividend.limbs_[j + i];
                        if (current < subtract) {
                            normalized_dividend.limbs_[j + i] =
                                static_cast<std::uint32_t>(base + current - subtract);
                            borrow = 1;
                        } else {
                            normalized_dividend.limbs_[j + i] = static_cast<std::uint32_t>(current - subtract);
                            borrow = 0;
                        }
                    }
                    const std::uint64_t high_subtract = carry + borrow;
                    const bool underflow = normalized_dividend.limbs_[j + n] < high_subtract;
                    normalized_dividend.limbs_[j + n] =
                        static_cast<std::uint32_t>(normalized_dividend.limbs_[j + n] - high_subtract);
                    if (underflow) {
                        --estimate;
                        std::uint64_t add_carry = 0;
                        for (std::size_t i = 0; i < n; ++i) {
                            const std::uint64_t sum = static_cast<std::uint64_t>(normalized_dividend.limbs_[j + i]) +
                                normalized_divisor.limbs_[i] + add_carry;
                            normalized_dividend.limbs_[j + i] = static_cast<std::uint32_t>(sum);
                            add_carry = sum >> 32U;
                        }
                        normalized_dividend.limbs_[j + n] =
                            static_cast<std::uint32_t>(normalized_dividend.limbs_[j + n] + add_carry);
                    }
                    quotient.limbs_[j] = static_cast<std::uint32_t>(estimate);
                }

                bigint remainder;
                remainder.limbs_.assign(normalized_dividend.limbs_.begin(), normalized_dividend.limbs_.begin() + n);
                remainder = remainder.shifted_right_abs(shift);
                quotient.normalize();
                remainder.normalize();
                return {quotient, remainder};
            }

            friend bigint raw_bitwise(const bigint&, const bigint&, char, std::size_t);
        };

        void ensure_integer_limit(const bigint& value)
        {
            if (value.bit_count() > CALC_MAX_BITS)
                fail("LIMIT_EXCEEDED", "integer exceeds 65536-bit limit");
        }

        bigint raw_bitwise(const bigint& lhs, const bigint& rhs, char operation, std::size_t bits)
        {
            bigint left = lhs.unsigned_mod(bits);
            bigint right = rhs.unsigned_mod(bits);
            bigint result;
            const std::size_t words = (bits + 31) / 32;
            result.limbs_.assign(words, 0);
            for (std::size_t i = 0; i < words; ++i) {
                checkpoint();
                const std::uint32_t a = i < left.limbs_.size() ? left.limbs_[i] : 0;
                const std::uint32_t b = i < right.limbs_.size() ? right.limbs_[i] : 0;
                if (operation == '&')
                    result.limbs_[i] = a & b;
                else if (operation == '|')
                    result.limbs_[i] = a | b;
                else
                    result.limbs_[i] = a ^ b;
            }
            result = result.low_bits(bits);
            return result;
        }

        bigint infinite_bitwise(const bigint& lhs, const bigint& rhs, char operation)
        {
            const std::size_t width = std::max(lhs.twos_width(), rhs.twos_width());
            if (width > k_internal_bits)
                fail("LIMIT_EXCEEDED", "bitwise operation exceeds integer limit");
            return bigint::from_twos_complement(raw_bitwise(lhs, rhs, operation, width), width);
        }

        bigint invert_fixed(const bigint& value, std::size_t bits)
        {
            return bigint::pow2(bits).subtracted(bigint::one()).subtracted(value.unsigned_mod(bits));
        }

        bool is_digit_for_base(char c, std::uint32_t base, std::uint32_t* digit)
        {
            std::uint32_t value = 0;
            if (c >= '0' && c <= '9')
                value = static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f')
                value = static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                value = static_cast<std::uint32_t>(c - 'A' + 10);
            else
                return false;
            if (value >= base)
                return false;
            if (digit)
                *digit = value;
            return true;
        }

        bigint parse_integer_spelling(const std::string& spelling)
        {
            if (spelling.empty())
                fail("PARSE_ERROR", "empty integer literal");
            std::size_t offset = 0;
            bool negative = false;
            if (spelling[offset] == '+' || spelling[offset] == '-') {
                negative = spelling[offset] == '-';
                if (++offset == spelling.size())
                    fail("PARSE_ERROR", "integer literal has no digits");
            }
            std::uint32_t base = 10;
            if (offset + 1 < spelling.size() && spelling[offset] == '0') {
                const char prefix = spelling[offset + 1];
                if (prefix == 'x' || prefix == 'X') {
                    base = 16;
                    offset += 2;
                } else if (prefix == 'o' || prefix == 'O') {
                    base = 8;
                    offset += 2;
                } else if (prefix == 'b' || prefix == 'B') {
                    base = 2;
                    offset += 2;
                }
            }
            if (offset == spelling.size())
                fail("PARSE_ERROR", "integer literal has no digits");
            bigint result;
            bool previous_separator = false;
            bool have_digit = false;
            for (; offset < spelling.size(); ++offset) {
                checkpoint();
                const char c = spelling[offset];
                if (c == '_') {
                    if (!have_digit || previous_separator)
                        fail("PARSE_ERROR", "invalid underscore in integer literal");
                    previous_separator = true;
                    continue;
                }
                std::uint32_t digit = 0;
                if (!is_digit_for_base(c, base, &digit))
                    fail("PARSE_ERROR", "invalid digit in integer literal");
                result.multiply_small(base);
                result.add_small(digit);
                ensure_integer_limit(result);
                previous_separator = false;
                have_digit = true;
            }
            if (!have_digit || previous_separator)
                fail("PARSE_ERROR", "integer literal has no digits");
            if (negative && !result.is_zero())
                return result.negated();
            return result;
        }

        std::size_t parse_bit_count(const bigint& value, const char* label, bool allow_zero = false)
        {
            if (value.is_negative() || value.bit_count() > 63)
                fail("RANGE_ERROR", std::string(label) + " must be a bounded non-negative integer");
            const std::uint64_t count = value.to_u64_checked();
            if ((!allow_zero && count == 0) || count > CALC_MAX_BITS)
                fail("RANGE_ERROR", std::string(label) + " must be between " + (allow_zero ? "0" : "1") + " and 65536");
            return static_cast<std::size_t>(count);
        }

        bool validate_utf8(const std::string& value)
        {
            const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
            std::size_t i = 0;
            while (i < value.size()) {
                const unsigned char first = bytes[i++];
                if (first <= 0x7F)
                    continue;
                auto continuation = [&](std::size_t count, unsigned char low, unsigned char high) {
                    if (i + count > value.size())
                        return false;
                    if (bytes[i] < low || bytes[i] > high)
                        return false;
                    ++i;
                    for (std::size_t j = 1; j < count; ++j) {
                        if ((bytes[i++] & 0xC0U) != 0x80U)
                            return false;
                    }
                    return true;
                };
                if (first >= 0xC2 && first <= 0xDF) {
                    if (!continuation(1, 0x80, 0xBF))
                        return false;
                } else if (first == 0xE0) {
                    if (!continuation(2, 0xA0, 0xBF))
                        return false;
                } else if ((first >= 0xE1 && first <= 0xEC) || (first >= 0xEE && first <= 0xEF)) {
                    if (!continuation(2, 0x80, 0xBF))
                        return false;
                } else if (first == 0xED) {
                    if (!continuation(2, 0x80, 0x9F))
                        return false;
                } else if (first == 0xF0) {
                    if (!continuation(3, 0x90, 0xBF))
                        return false;
                } else if (first >= 0xF1 && first <= 0xF3) {
                    if (!continuation(3, 0x80, 0xBF))
                        return false;
                } else if (first == 0xF4) {
                    if (!continuation(3, 0x80, 0x8F))
                        return false;
                } else {
                    return false;
                }
            }
            return true;
        }

        bool printable_ascii(const std::vector<std::uint8_t>& bytes)
        {
            return !bytes.empty() && std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) {
                return byte >= 0x20 && byte <= 0x7E;
            });
        }

        std::vector<std::uint8_t> parse_hex_bytes(const std::string& text)
        {
            std::string digits;
            digits.reserve(text.size());
            for (char c : text) {
                if (std::isxdigit(static_cast<unsigned char>(c)))
                    digits.push_back(c);
                else if (!(std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-' || c == '_'))
                    fail("PARSE_ERROR", "byte literal contains an invalid character");
            }
            if (digits.empty() || (digits.size() & 1U) != 0)
                fail("PARSE_ERROR", "byte literal must contain complete hexadecimal byte pairs");
            if (digits.size() / 2 > k_max_blob_bytes)
                fail("LIMIT_EXCEEDED", "byte literal exceeds size limit");
            std::vector<std::uint8_t> result;
            result.reserve(digits.size() / 2);
            for (std::size_t i = 0; i < digits.size(); i += 2) {
                std::uint32_t high = 0;
                std::uint32_t low = 0;
                (void)is_digit_for_base(digits[i], 16, &high);
                (void)is_digit_for_base(digits[i + 1], 16, &low);
                result.push_back(static_cast<std::uint8_t>((high << 4U) | low));
            }
            return result;
        }

        std::string hex_bytes(const std::vector<std::uint8_t>& bytes)
        {
            static constexpr char digits[] = "0123456789ABCDEF";
            std::string result;
            result.reserve(2 + bytes.size() * 2);
            result.append("0x");
            for (std::uint8_t byte : bytes) {
                result.push_back(digits[byte >> 4U]);
                result.push_back(digits[byte & 0x0FU]);
            }
            return result;
        }

        enum class value_kind
        {
            integer,
            bytes,
            text,
            floating
        };

        struct calc_value
        {
            value_kind kind = value_kind::integer;
            bigint integer;
            std::vector<std::uint8_t> bytes;
            std::string text;
            double floating = 0.0;
            std::size_t floating_width = 0;
            bigint floating_bits;

            static calc_value from_integer(bigint value)
            {
                calc_value result;
                result.integer = std::move(value);
                return result;
            }

            static calc_value from_bytes(std::vector<std::uint8_t> value)
            {
                calc_value result;
                result.kind = value_kind::bytes;
                result.bytes = std::move(value);
                return result;
            }

            static calc_value from_text(std::string value)
            {
                calc_value result;
                result.kind = value_kind::text;
                result.text = std::move(value);
                return result;
            }

            static calc_value from_floating(double value, std::size_t width, bigint bits)
            {
                calc_value result;
                result.kind = value_kind::floating;
                result.floating = value;
                result.floating_width = width;
                result.floating_bits = std::move(bits);
                return result;
            }
        };

        struct section_mapping_t
        {
            bigint rva_start;
            bigint virtual_size;
            bigint raw_offset;
            bigint raw_size;
        };

        struct mapping_t
        {
            bool has_image_base = false;
            bigint image_base;
            std::vector<section_mapping_t> sections;
        };

        struct environment_t
        {
            std::unordered_map<std::string, calc_value> variables;
            mapping_t mapping;
        };

        bigint parse_json_integer(const json& value, const char* label)
        {
            if (value.is_string())
                return parse_integer_spelling(value.get<std::string>());
            if (value.is_number_unsigned())
                return bigint(value.get<std::uint64_t>());
            if (value.is_number_integer()) {
                const std::int64_t number = value.get<std::int64_t>();
                const std::uint64_t magnitude = number < 0
                    ? static_cast<std::uint64_t>(-(number + 1)) + 1U
                    : static_cast<std::uint64_t>(number);
                bigint result(magnitude);
                return number < 0 ? result.negated() : result;
            }
            fail("INVALID_ARGUMENT", std::string(label) + " must be an integer string or JSON integer");
        }

        calc_value parse_variable_value(const json& value, const std::string& name)
        {
            if (value.is_string() || value.is_number_integer() || value.is_number_unsigned())
                return calc_value::from_integer(parse_json_integer(value, name.c_str()));
            if (!value.is_object())
                fail("INVALID_ARGUMENT", "variable " + name + " must be integer data or a typed data object");
            if (value.contains("integer"))
                return calc_value::from_integer(parse_json_integer(value.at("integer"), name.c_str()));
            if (value.contains("bytes")) {
                if (!value.at("bytes").is_string())
                    fail("INVALID_ARGUMENT", "bytes variable must be a hexadecimal string");
                return calc_value::from_bytes(parse_hex_bytes(value.at("bytes").get<std::string>()));
            }
            if (value.contains("ascii")) {
                if (!value.at("ascii").is_string())
                    fail("INVALID_ARGUMENT", "ascii variable must be a string");
                const std::string text = value.at("ascii").get<std::string>();
                if (text.size() > k_max_blob_bytes || !std::all_of(text.begin(), text.end(), [](char c) {
                    return static_cast<unsigned char>(c) <= 0x7F;
                }))
                    fail("INVALID_ARGUMENT", "ascii variable contains non-ASCII data");
                return calc_value::from_bytes(std::vector<std::uint8_t>(text.begin(), text.end()));
            }
            if (value.contains("utf8")) {
                if (!value.at("utf8").is_string())
                    fail("INVALID_ARGUMENT", "utf8 variable must be a string");
                const std::string text = value.at("utf8").get<std::string>();
                if (text.size() > k_max_blob_bytes || !validate_utf8(text))
                    fail("INVALID_ARGUMENT", "utf8 variable contains invalid UTF-8 data");
                return calc_value::from_bytes(std::vector<std::uint8_t>(text.begin(), text.end()));
            }
            fail("INVALID_ARGUMENT", "variable " + name + " has no supported data field");
        }

        void add_variables(environment_t& environment, const json& variables)
        {
            if (variables.is_null())
                return;
            if (!variables.is_object())
                fail("INVALID_ARGUMENT", "variables must be an object");
            for (auto it = variables.begin(); it != variables.end(); ++it) {
                if (!valid_identifier(it.key()))
                    fail("INVALID_ARGUMENT", "variable name is invalid: " + it.key());
                environment.variables[it.key()] = parse_variable_value(it.value(), it.key());
            }
        }

        bigint positive_mapping_value(const json& object, const char* key, bool required)
        {
            if (!object.contains(key)) {
                if (required)
                    fail("INVALID_ARGUMENT", std::string("mapping field is required: ") + key);
                return bigint();
            }
            bigint result = parse_json_integer(object.at(key), key);
            if (result.is_negative())
                fail("INVALID_ARGUMENT", std::string("mapping field must be non-negative: ") + key);
            return result;
        }

        mapping_t parse_mapping(const json& mapping)
        {
            mapping_t result;
            if (mapping.is_null())
                return result;
            if (!mapping.is_object())
                fail("INVALID_ARGUMENT", "mapping must be an object");
            if (mapping.contains("image_base")) {
                result.image_base = positive_mapping_value(mapping, "image_base", true);
                result.has_image_base = true;
            }
            if (!mapping.contains("sections"))
                return result;
            if (!mapping.at("sections").is_array())
                fail("INVALID_ARGUMENT", "mapping sections must be an array");
            if (mapping.at("sections").size() > 1024)
                fail("LIMIT_EXCEEDED", "mapping has too many sections");
            for (const json& section : mapping.at("sections")) {
                if (!section.is_object())
                    fail("INVALID_ARGUMENT", "mapping section must be an object");
                section_mapping_t parsed;
                if (section.contains("rva_start")) {
                    parsed.rva_start = positive_mapping_value(section, "rva_start", true);
                } else if (section.contains("va_start") && result.has_image_base) {
                    const bigint address = positive_mapping_value(section, "va_start", true);
                    if (address.compare(result.image_base) < 0)
                        fail("INVALID_ARGUMENT", "section VA starts below image base");
                    parsed.rva_start = address.subtracted(result.image_base);
                } else {
                    fail("INVALID_ARGUMENT", "mapping section requires rva_start or va_start with image_base");
                }
                parsed.virtual_size = positive_mapping_value(section, "virtual_size", true);
                parsed.raw_offset = positive_mapping_value(section, "raw_offset", true);
                parsed.raw_size = positive_mapping_value(section, "raw_size", true);
                result.sections.push_back(std::move(parsed));
            }
            return result;
        }

        bool mapping_contains(const bigint& value, const bigint& start, const bigint& length)
        {
            if (length.is_zero() || value.compare(start) < 0)
                return false;
            return value.subtracted(start).compare(length) < 0;
        }

        enum class token_kind
        {
            integer,
            floating,
            text,
            identifier,
            operation,
            left_paren,
            right_paren,
            comma,
            end
        };

        struct token_t
        {
            token_kind kind = token_kind::end;
            std::string text;
            bigint integer;
            double floating = 0.0;
        };

        class tokenizer_t
        {
        public:
            explicit tokenizer_t(const std::string& source)
                : source_(source)
            {
            }

            token_t next()
            {
                checkpoint();
                skip_space();
                if (position_ >= source_.size())
                    return emit({token_kind::end});
                const char current = source_[position_];
                if (current == '(') {
                    ++position_;
                    return emit({token_kind::left_paren, "("});
                }
                if (current == ')') {
                    ++position_;
                    return emit({token_kind::right_paren, ")"});
                }
                if (current == ',') {
                    ++position_;
                    return emit({token_kind::comma, ","});
                }
                if (current == '\'' || current == '"')
                    return emit(read_text());
                if (std::isdigit(static_cast<unsigned char>(current)))
                    return emit(read_number());
                if (std::isalpha(static_cast<unsigned char>(current)) || current == '_')
                    return emit(read_identifier());
                if (position_ + 1 < source_.size()) {
                    const std::string pair = source_.substr(position_, 2);
                    if (pair == "<<" || pair == ">>") {
                        position_ += 2;
                        return emit({token_kind::operation, pair});
                    }
                }
                if (std::string("+-*/%&|^~").find(current) != std::string::npos) {
                    ++position_;
                    return emit({token_kind::operation, std::string(1, current)});
                }
                fail("PARSE_ERROR", "unexpected character in expression");
            }

        private:
            const std::string& source_;
            std::size_t position_ = 0;
            std::size_t token_count_ = 0;

            token_t emit(token_t token)
            {
                if (++token_count_ > CALC_MAX_TOKENS)
                    fail("LIMIT_EXCEEDED", "expression exceeds 4096-token limit");
                return token;
            }

            void skip_space()
            {
                while (position_ < source_.size() && std::isspace(static_cast<unsigned char>(source_[position_])))
                    ++position_;
            }

            token_t read_identifier()
            {
                const std::size_t start = position_;
                while (position_ < source_.size() &&
                       (std::isalnum(static_cast<unsigned char>(source_[position_])) || source_[position_] == '_'))
                    ++position_;
                return {token_kind::identifier, source_.substr(start, position_ - start)};
            }

            token_t read_text()
            {
                const char quote = source_[position_++];
                std::string value;
                while (position_ < source_.size()) {
                    const unsigned char current = static_cast<unsigned char>(source_[position_++]);
                    if (current == static_cast<unsigned char>(quote))
                        return {token_kind::text, std::move(value)};
                    if (current < 0x20)
                        fail("PARSE_ERROR", "string literal contains an unescaped control character");
                    if (current != '\\') {
                        value.push_back(static_cast<char>(current));
                    } else {
                        if (position_ >= source_.size())
                            fail("PARSE_ERROR", "unterminated string escape");
                        const char escaped = source_[position_++];
                        if (escaped == 'n')
                            value.push_back('\n');
                        else if (escaped == 'r')
                            value.push_back('\r');
                        else if (escaped == 't')
                            value.push_back('\t');
                        else if (escaped == '0')
                            value.push_back('\0');
                        else if (escaped == '\\' || escaped == '\'' || escaped == '"')
                            value.push_back(escaped);
                        else if (escaped == 'x') {
                            if (position_ + 1 >= source_.size())
                                fail("PARSE_ERROR", "incomplete hexadecimal string escape");
                            std::uint32_t high = 0;
                            std::uint32_t low = 0;
                            if (!is_digit_for_base(source_[position_], 16, &high) ||
                                !is_digit_for_base(source_[position_ + 1], 16, &low))
                                fail("PARSE_ERROR", "invalid hexadecimal string escape");
                            position_ += 2;
                            value.push_back(static_cast<char>((high << 4U) | low));
                        } else {
                            fail("PARSE_ERROR", "unsupported string escape");
                        }
                    }
                    if (value.size() > k_max_blob_bytes)
                        fail("LIMIT_EXCEEDED", "string literal exceeds size limit");
                }
                fail("PARSE_ERROR", "unterminated string literal");
            }

            token_t read_number()
            {
                const std::size_t start = position_;
                if (position_ + 1 < source_.size() && source_[position_] == '0' &&
                    (source_[position_ + 1] == 'x' || source_[position_ + 1] == 'X' ||
                     source_[position_ + 1] == 'o' || source_[position_ + 1] == 'O' ||
                     source_[position_ + 1] == 'b' || source_[position_ + 1] == 'B')) {
                    position_ += 2;
                    while (position_ < source_.size() &&
                           (std::isalnum(static_cast<unsigned char>(source_[position_])) || source_[position_] == '_'))
                        ++position_;
                    const std::string spelling = source_.substr(start, position_ - start);
                    return {token_kind::integer, spelling, parse_integer_spelling(spelling)};
                }

                while (position_ < source_.size() &&
                       (std::isdigit(static_cast<unsigned char>(source_[position_])) || source_[position_] == '_'))
                    ++position_;
                bool floating = false;
                if (position_ < source_.size() && source_[position_] == '.') {
                    floating = true;
                    ++position_;
                    while (position_ < source_.size() &&
                           (std::isdigit(static_cast<unsigned char>(source_[position_])) || source_[position_] == '_'))
                        ++position_;
                }
                if (position_ < source_.size() && (source_[position_] == 'e' || source_[position_] == 'E')) {
                    floating = true;
                    ++position_;
                    if (position_ < source_.size() && (source_[position_] == '+' || source_[position_] == '-'))
                        ++position_;
                    while (position_ < source_.size() &&
                           (std::isdigit(static_cast<unsigned char>(source_[position_])) || source_[position_] == '_'))
                        ++position_;
                }
                const std::string spelling = source_.substr(start, position_ - start);
                if (!floating)
                    return {token_kind::integer, spelling, parse_integer_spelling(spelling)};
                std::string clean;
                clean.reserve(spelling.size());
                for (char c : spelling) {
                    if (c != '_')
                        clean.push_back(c);
                }
                char* end = nullptr;
                const double value = std::strtod(clean.c_str(), &end);
                if (end == nullptr || *end != '\0' || !std::isfinite(value))
                    fail("PARSE_ERROR", "invalid finite floating-point literal");
                return {token_kind::floating, spelling, {}, value};
            }
        };

        struct calculation_options_t
        {
            std::size_t bit_width = 0;
            bool signed_result = false;
        };

        calculation_options_t parse_options(const json& object, calculation_options_t base = {})
        {
            if (!object.is_object())
                fail("INVALID_ARGUMENT", "calculation item must be an object");
            const char* width_key = object.contains("bits") ? "bits" : (object.contains("width") ? "width" : nullptr);
            if (width_key) {
                bigint width = parse_json_integer(object.at(width_key), width_key);
                base.bit_width = parse_bit_count(width, width_key);
            }
            if (object.contains("signed")) {
                const json& signed_value = object.at("signed");
                if (signed_value.is_boolean()) {
                    base.signed_result = signed_value.get<bool>();
                } else if (signed_value.is_string()) {
                    const std::string mode = lower_ascii(signed_value.get<std::string>());
                    if (mode == "signed")
                        base.signed_result = true;
                    else if (mode == "unsigned")
                        base.signed_result = false;
                    else
                        fail("INVALID_ARGUMENT", "signed must be a boolean, signed, or unsigned");
                } else {
                    fail("INVALID_ARGUMENT", "signed must be a boolean, signed, or unsigned");
                }
            }
            return base;
        }

        std::uint32_t crc32(const std::vector<std::uint8_t>& data)
        {
            std::uint32_t result = 0xFFFFFFFFU;
            for (std::uint8_t byte : data) {
                checkpoint();
                result ^= byte;
                for (unsigned int i = 0; i < 8; ++i)
                    result = (result & 1U) != 0 ? (result >> 1U) ^ 0xEDB88320U : result >> 1U;
            }
            return result ^ 0xFFFFFFFFU;
        }

        std::uint32_t adler32(const std::vector<std::uint8_t>& data)
        {
            std::uint32_t a = 1;
            std::uint32_t b = 0;
            for (std::uint8_t byte : data) {
                checkpoint();
                a = (a + byte) % 65521U;
                b = (b + a) % 65521U;
            }
            return (b << 16U) | a;
        }

        std::uint32_t fnv1a32(const std::vector<std::uint8_t>& data)
        {
            std::uint32_t result = 0x811C9DC5U;
            for (std::uint8_t byte : data) {
                checkpoint();
                result ^= byte;
                result *= 0x01000193U;
            }
            return result;
        }

        std::uint64_t fnv1a64(const std::vector<std::uint8_t>& data)
        {
            std::uint64_t result = 0xCBF29CE484222325ULL;
            for (std::uint8_t byte : data) {
                checkpoint();
                result ^= byte;
                result *= 0x100000001B3ULL;
            }
            return result;
        }

        std::uint16_t double_to_half(double value)
        {
            const float narrowed = static_cast<float>(value);
            std::uint32_t bits = 0;
            std::memcpy(&bits, &narrowed, sizeof(bits));
            const std::uint32_t sign = (bits >> 16U) & 0x8000U;
            const std::uint32_t exponent = (bits >> 23U) & 0xFFU;
            const std::uint32_t fraction = bits & 0x7FFFFFU;
            if (exponent == 0xFFU)
                return static_cast<std::uint16_t>(sign | (fraction == 0 ? 0x7C00U : 0x7E00U));
            const int half_exponent = static_cast<int>(exponent) - 127 + 15;
            if (half_exponent >= 31)
                return static_cast<std::uint16_t>(sign | 0x7C00U);
            if (half_exponent <= 0) {
                if (half_exponent < -10)
                    return static_cast<std::uint16_t>(sign);
                std::uint32_t mantissa = fraction | 0x800000U;
                const unsigned int shift = static_cast<unsigned int>(14 - half_exponent);
                std::uint32_t rounded = mantissa >> shift;
                if ((mantissa >> (shift - 1U)) & 1U)
                    ++rounded;
                return static_cast<std::uint16_t>(sign | rounded);
            }
            std::uint32_t rounded_fraction = fraction >> 13U;
            if (fraction & 0x1000U) {
                ++rounded_fraction;
                if (rounded_fraction == 0x400U)
                    return static_cast<std::uint16_t>(sign | ((half_exponent + 1) << 10U));
            }
            return static_cast<std::uint16_t>(sign | (static_cast<std::uint32_t>(half_exponent) << 10U) | rounded_fraction);
        }

        double half_to_double(std::uint16_t bits)
        {
            const std::uint32_t sign = (static_cast<std::uint32_t>(bits) & 0x8000U) << 16U;
            const std::uint32_t exponent = (bits >> 10U) & 0x1FU;
            const std::uint32_t fraction = bits & 0x3FFU;
            std::uint32_t result = 0;
            if (exponent == 0) {
                if (fraction == 0) {
                    result = sign;
                } else {
                    std::uint32_t mantissa = fraction;
                    int adjusted_exponent = -14;
                    while ((mantissa & 0x400U) == 0) {
                        mantissa <<= 1U;
                        --adjusted_exponent;
                    }
                    mantissa &= 0x3FFU;
                    result = sign | (static_cast<std::uint32_t>(adjusted_exponent + 127) << 23U) | (mantissa << 13U);
                }
            } else if (exponent == 0x1FU) {
                result = sign | 0x7F800000U | (fraction << 13U);
            } else {
                result = sign | ((exponent + 112U) << 23U) | (fraction << 13U);
            }
            float output = 0.0F;
            std::memcpy(&output, &result, sizeof(output));
            return static_cast<double>(output);
        }

        std::string floating_to_string(double value)
        {
            if (std::isnan(value))
                return "nan";
            if (std::isinf(value))
                return value < 0 ? "-inf" : "inf";
            std::ostringstream stream;
            stream << std::setprecision(std::numeric_limits<double>::max_digits10) << value;
            return stream.str();
        }

        class parser_t
        {
        public:
            parser_t(const std::string& expression, const environment_t& environment,
                     calculation_options_t options)
                : tokenizer_(expression), environment_(environment), options_(options)
            {
                current_ = tokenizer_.next();
            }

            calc_value parse()
            {
                calc_value result = parse_or();
                if (current_.kind != token_kind::end)
                    fail("PARSE_ERROR", "trailing token in expression");
                return result;
            }

        private:
            tokenizer_t tokenizer_;
            token_t current_;
            const environment_t& environment_;
            calculation_options_t options_;
            std::size_t nesting_ = 0;

            void advance()
            {
                current_ = tokenizer_.next();
            }

            void enter_nesting()
            {
                if (++nesting_ > CALC_MAX_NESTING)
                    fail("LIMIT_EXCEEDED", "expression exceeds 128 nesting levels");
            }

            void leave_nesting()
            {
                --nesting_;
            }

            const bigint& require_integer(const calc_value& value, const char* operation) const
            {
                if (value.kind != value_kind::integer)
                    fail("TYPE_ERROR", std::string(operation) + " requires integer arguments");
                return value.integer;
            }

            bigint apply_width(bigint value) const
            {
                if (options_.bit_width != 0)
                    value = value.unsigned_mod(options_.bit_width);
                ensure_integer_limit(value);
                return value;
            }

            calc_value integer_result(bigint value) const
            {
                return calc_value::from_integer(apply_width(std::move(value)));
            }

            std::size_t shift_amount(const bigint& value) const
            {
                if (value.is_negative() || value.bit_count() > 63)
                    fail("RANGE_ERROR", "shift amount must be a bounded non-negative integer");
                const std::uint64_t amount = value.to_u64_checked();
                if (amount > CALC_MAX_BITS)
                    fail("RANGE_ERROR", "shift amount exceeds 65536 bits");
                return static_cast<std::size_t>(amount);
            }

            calc_value parse_or()
            {
                calc_value value = parse_xor();
                while (current_.kind == token_kind::operation && current_.text == "|") {
                    advance();
                    value = binary_integer(value, parse_xor(), '|');
                }
                return value;
            }

            calc_value parse_xor()
            {
                calc_value value = parse_and();
                while (current_.kind == token_kind::operation && current_.text == "^") {
                    advance();
                    value = binary_integer(value, parse_and(), '^');
                }
                return value;
            }

            calc_value parse_and()
            {
                calc_value value = parse_shift();
                while (current_.kind == token_kind::operation && current_.text == "&") {
                    advance();
                    value = binary_integer(value, parse_shift(), '&');
                }
                return value;
            }

            calc_value parse_shift()
            {
                calc_value value = parse_add();
                while (current_.kind == token_kind::operation && (current_.text == "<<" || current_.text == ">>")) {
                    const bool left = current_.text == "<<";
                    advance();
                    const std::size_t amount = shift_amount(require_integer(parse_add(), "shift"));
                    bigint source = require_integer(value, "shift");
                    if (options_.bit_width == 0) {
                        value = integer_result(left ? source.shifted_left(amount) : source.shifted_right_arithmetic(amount));
                    } else {
                        const bigint raw = source.unsigned_mod(options_.bit_width);
                        if (left) {
                            value = integer_result(raw.shifted_left(amount));
                        } else if (options_.signed_result) {
                            const bigint signed_value = bigint::from_twos_complement(raw, options_.bit_width);
                            value = integer_result(signed_value.shifted_right_arithmetic(amount));
                        } else {
                            value = integer_result(raw.shifted_right_arithmetic(amount));
                        }
                    }
                }
                return value;
            }

            calc_value parse_add()
            {
                calc_value value = parse_multiply();
                while (current_.kind == token_kind::operation && (current_.text == "+" || current_.text == "-")) {
                    const char operation = current_.text.front();
                    advance();
                    value = binary_integer(value, parse_multiply(), operation);
                }
                return value;
            }

            calc_value parse_multiply()
            {
                calc_value value = parse_unary();
                while (current_.kind == token_kind::operation &&
                       (current_.text == "*" || current_.text == "/" || current_.text == "%")) {
                    const char operation = current_.text.front();
                    advance();
                    value = binary_integer(value, parse_unary(), operation);
                }
                return value;
            }

            calc_value parse_unary()
            {
                if (current_.kind == token_kind::operation) {
                    const char operation = current_.text.front();
                    if (operation == '+' || operation == '-' || operation == '~') {
                        advance();
                        calc_value value = parse_unary();
                        const bigint& integer = require_integer(value, "unary operation");
                        if (operation == '+')
                            return integer_result(integer);
                        if (operation == '-')
                            return integer_result(integer.negated());
                        if (options_.bit_width != 0)
                            return integer_result(invert_fixed(integer, options_.bit_width));
                        return integer_result(integer.negated().subtracted(bigint::one()));
                    }
                }
                return parse_primary();
            }

            calc_value parse_primary()
            {
                if (current_.kind == token_kind::integer) {
                    bigint value = current_.integer;
                    advance();
                    return integer_result(std::move(value));
                }
                if (current_.kind == token_kind::floating) {
                    const double value = current_.floating;
                    advance();
                    return calc_value::from_floating(value, 64, bigint());
                }
                if (current_.kind == token_kind::text) {
                    std::string value = current_.text;
                    advance();
                    return calc_value::from_text(std::move(value));
                }
                if (current_.kind == token_kind::left_paren) {
                    advance();
                    enter_nesting();
                    calc_value value = parse_or();
                    leave_nesting();
                    if (current_.kind != token_kind::right_paren)
                        fail("PARSE_ERROR", "expected closing parenthesis");
                    advance();
                    return value;
                }
                if (current_.kind == token_kind::identifier) {
                    const std::string name = current_.text;
                    advance();
                    if (current_.kind == token_kind::left_paren)
                        return parse_call(lower_ascii(name));
                    const auto found = environment_.variables.find(name);
                    if (found != environment_.variables.end()) {
                        calc_value value = found->second;
                        if (value.kind == value_kind::integer)
                            value.integer = apply_width(std::move(value.integer));
                        return value;
                    }
                    if (name == "image_base" && environment_.mapping.has_image_base)
                        return integer_result(environment_.mapping.image_base);
                    fail("UNKNOWN_IDENTIFIER", "unknown variable: " + name);
                }
                fail("PARSE_ERROR", "expected an expression value");
            }

            calc_value parse_call(const std::string& name)
            {
                if (current_.kind != token_kind::left_paren)
                    fail("PARSE_ERROR", "expected function opening parenthesis");
                advance();
                enter_nesting();
                std::vector<calc_value> arguments;
                if (current_.kind != token_kind::right_paren) {
                    for (;;) {
                        arguments.push_back(parse_or());
                        if (current_.kind != token_kind::comma)
                            break;
                        advance();
                    }
                }
                leave_nesting();
                if (current_.kind != token_kind::right_paren)
                    fail("PARSE_ERROR", "expected function closing parenthesis");
                advance();
                return evaluate_call(name, arguments);
            }

            calc_value binary_integer(const calc_value& left, const calc_value& right, char operation) const
            {
                const bigint& lhs = require_integer(left, "arithmetic operation");
                const bigint& rhs = require_integer(right, "arithmetic operation");
                if (options_.bit_width != 0) {
                    const bigint raw_left = lhs.unsigned_mod(options_.bit_width);
                    const bigint raw_right = rhs.unsigned_mod(options_.bit_width);
                    if (operation == '&' || operation == '|' || operation == '^')
                        return integer_result(raw_bitwise(raw_left, raw_right, operation, options_.bit_width));
                    if (operation == '/' || operation == '%') {
                        const bigint dividend = options_.signed_result
                            ? bigint::from_twos_complement(raw_left, options_.bit_width)
                            : raw_left;
                        const bigint divisor = options_.signed_result
                            ? bigint::from_twos_complement(raw_right, options_.bit_width)
                            : raw_right;
                        const auto division = bigint::divide_with_remainder(dividend, divisor);
                        return integer_result(operation == '/' ? division.first : division.second);
                    }
                    if (operation == '+')
                        return integer_result(raw_left.added(raw_right));
                    if (operation == '-')
                        return integer_result(raw_left.subtracted(raw_right));
                    if (operation == '*')
                        return integer_result(raw_left.multiplied(raw_right));
                    fail("PARSE_ERROR", "unsupported binary operation");
                }
                if (operation == '&' || operation == '|' || operation == '^')
                    return integer_result(infinite_bitwise(lhs, rhs, operation));
                if (operation == '/')
                    return integer_result(bigint::divide_with_remainder(lhs, rhs).first);
                if (operation == '%')
                    return integer_result(bigint::divide_with_remainder(lhs, rhs).second);
                if (operation == '+')
                    return integer_result(lhs.added(rhs));
                if (operation == '-')
                    return integer_result(lhs.subtracted(rhs));
                if (operation == '*')
                    return integer_result(lhs.multiplied(rhs));
                fail("PARSE_ERROR", "unsupported binary operation");
            }

            void require_count(const std::string& name, const std::vector<calc_value>& arguments,
                               std::size_t minimum, std::size_t maximum) const
            {
                if (arguments.size() < minimum || arguments.size() > maximum)
                    fail("ARITY_ERROR", name + " received an invalid argument count");
            }

            const bigint& integer_argument(const std::string& name, const std::vector<calc_value>& arguments,
                                           std::size_t index) const
            {
                if (index >= arguments.size())
                    fail("ARITY_ERROR", name + " is missing an argument");
                return require_integer(arguments[index], name.c_str());
            }

            std::size_t width_argument(const std::string& name, const std::vector<calc_value>& arguments,
                                       std::size_t index, bool allow_zero = false) const
            {
                return parse_bit_count(integer_argument(name, arguments, index), "bit width", allow_zero);
            }

            std::vector<std::uint8_t> explicit_bytes_argument(const std::string& name,
                                                              const std::vector<calc_value>& arguments,
                                                              std::size_t index) const
            {
                if (index >= arguments.size())
                    fail("ARITY_ERROR", name + " is missing an argument");
                const calc_value& value = arguments[index];
                if (value.kind == value_kind::bytes)
                    return value.bytes;
                if (value.kind == value_kind::text)
                    return std::vector<std::uint8_t>(value.text.begin(), value.text.end());
                fail("TYPE_ERROR", name + " requires an explicit bytes or string literal");
            }

            bool big_endian_argument(const std::string& name, const std::vector<calc_value>& arguments,
                                     std::size_t index, bool default_value) const
            {
                if (index >= arguments.size())
                    return default_value;
                const calc_value& value = arguments[index];
                if (value.kind == value_kind::integer) {
                    const bigint& integer = value.integer;
                    if (integer.is_negative() || integer.bit_count() > 1)
                        fail("INVALID_ARGUMENT", name + " endianness integer must be 0 or 1");
                    return !integer.is_zero();
                }
                if (value.kind == value_kind::text) {
                    const std::string order = lower_ascii(value.text);
                    if (order == "be" || order == "big" || order == "big_endian")
                        return true;
                    if (order == "le" || order == "little" || order == "little_endian")
                        return false;
                }
                fail("INVALID_ARGUMENT", name + " endianness must be little/le/0 or big/be/1");
            }

            bool boolean_argument(const std::string& name, const std::vector<calc_value>& arguments,
                                  std::size_t index, bool default_value) const
            {
                if (index >= arguments.size())
                    return default_value;
                const bigint& value = integer_argument(name, arguments, index);
                if (value.is_negative() || value.bit_count() > 1)
                    fail("INVALID_ARGUMENT", name + " boolean argument must be 0 or 1");
                return !value.is_zero();
            }

            std::vector<std::uint8_t> integer_to_bytes(const bigint& value, std::size_t byte_count, bool big_endian) const
            {
                if (byte_count == 0 || byte_count > k_max_integer_bytes)
                    fail("RANGE_ERROR", "byte count must be between 1 and 8192");
            bigint raw = value.unsigned_mod(byte_count * 8);
            if (!value.is_negative() && value.bit_count() > byte_count * 8)
                fail("RANGE_ERROR", "integer does not fit requested byte count");
                std::vector<std::uint8_t> result(byte_count, 0);
                for (std::size_t i = 0; i < byte_count; ++i) {
                    const bigint byte = raw.low_bits(8);
                    result[i] = static_cast<std::uint8_t>(byte.to_u64_checked());
                    raw = raw.shifted_right_arithmetic(8);
                }
                if (big_endian)
                    std::reverse(result.begin(), result.end());
                return result;
            }

            bigint bytes_to_integer(const std::vector<std::uint8_t>& bytes, bool big_endian, bool signed_value) const
            {
                if (bytes.empty() || bytes.size() > k_max_integer_bytes)
                    fail("RANGE_ERROR", "byte sequence must contain between 1 and 8192 bytes");
                bigint result;
                if (big_endian) {
                    for (std::uint8_t byte : bytes) {
                        checkpoint();
                        result = result.shifted_left(8);
                        result.add_small(byte);
                    }
                } else {
                    for (std::size_t i = bytes.size(); i > 0; --i) {
                        checkpoint();
                        result = result.shifted_left(8);
                        result.add_small(bytes[i - 1]);
                    }
                }
                if (signed_value)
                    result = bigint::from_twos_complement(result, bytes.size() * 8);
                return result;
            }

            double argument_as_double(const std::string& name, const std::vector<calc_value>& arguments,
                                      std::size_t index) const
            {
                if (index >= arguments.size())
                    fail("ARITY_ERROR", name + " is missing an argument");
                const calc_value& value = arguments[index];
                if (value.kind == value_kind::floating)
                    return value.floating;
                if (value.kind == value_kind::integer) {
                    const std::string text = value.integer.to_decimal();
                    char* end = nullptr;
                    const double converted = std::strtod(text.c_str(), &end);
                    if (end == nullptr || *end != '\0' || !std::isfinite(converted))
                        fail("RANGE_ERROR", name + " integer cannot be represented as a finite float");
                    return converted;
                }
                fail("TYPE_ERROR", name + " requires a numeric argument");
            }

            std::size_t floating_width(const std::string& name, const std::vector<calc_value>& arguments,
                                       std::size_t index, std::size_t default_width) const
            {
                if (index >= arguments.size())
                    return default_width;
                const std::size_t width = width_argument(name, arguments, index);
                if (width != 16 && width != 32 && width != 64)
                    fail("RANGE_ERROR", name + " floating width must be 16, 32, or 64");
                return width;
            }

            calc_value float_to_bits(const std::string& name, const std::vector<calc_value>& arguments,
                                     std::size_t default_width) const
            {
                require_count(name, arguments, 1, 2);
                const double value = argument_as_double(name, arguments, 0);
                const std::size_t width = floating_width(name, arguments, 1, default_width);
                if (width == 16)
                    return integer_result(bigint(double_to_half(value)));
                if (width == 32) {
                    const float narrowed = static_cast<float>(value);
                    std::uint32_t bits = 0;
                    std::memcpy(&bits, &narrowed, sizeof(bits));
                    return integer_result(bigint(bits));
                }
                std::uint64_t bits = 0;
                std::memcpy(&bits, &value, sizeof(bits));
                return integer_result(bigint(bits));
            }

            calc_value bits_to_float(const std::string& name, const std::vector<calc_value>& arguments,
                                     std::size_t default_width) const
            {
                require_count(name, arguments, 1, 2);
                const std::size_t width = floating_width(name, arguments, 1, default_width);
                const bigint bits = integer_argument(name, arguments, 0).unsigned_mod(width);
                const std::uint64_t raw = bits.to_u64_checked();
                if (width == 16)
                    return calc_value::from_floating(half_to_double(static_cast<std::uint16_t>(raw)), width, bits);
                if (width == 32) {
                    const std::uint32_t raw32 = static_cast<std::uint32_t>(raw);
                    float value = 0.0F;
                    std::memcpy(&value, &raw32, sizeof(value));
                    return calc_value::from_floating(static_cast<double>(value), width, bits);
                }
                double value = 0.0;
                std::memcpy(&value, &raw, sizeof(value));
                return calc_value::from_floating(value, width, bits);
            }

            bigint va_to_rva(const bigint& value) const
            {
                if (!environment_.mapping.has_image_base)
                    fail("MAPPING_REQUIRED", "va_to_rva requires mapping.image_base");
                if (value.compare(environment_.mapping.image_base) < 0)
                    fail("RANGE_ERROR", "VA is below image base");
                return value.subtracted(environment_.mapping.image_base);
            }

            bigint rva_to_va(const bigint& value) const
            {
                if (!environment_.mapping.has_image_base)
                    fail("MAPPING_REQUIRED", "rva_to_va requires mapping.image_base");
                return value.added(environment_.mapping.image_base);
            }

            bigint rva_to_file_offset(const bigint& value) const
            {
                for (const section_mapping_t& section : environment_.mapping.sections) {
                    checkpoint();
                    if (mapping_contains(value, section.rva_start, section.raw_size))
                        return section.raw_offset.added(value.subtracted(section.rva_start));
                    if (mapping_contains(value, section.rva_start, section.virtual_size))
                        fail("MAPPING_NOT_FOUND", "RVA resolves to virtual-only section data with no file offset");
                }
                fail("MAPPING_NOT_FOUND", "RVA is not backed by an explicit section raw range");
            }

            bigint file_offset_to_rva(const bigint& value) const
            {
                for (const section_mapping_t& section : environment_.mapping.sections) {
                    checkpoint();
                    if (mapping_contains(value, section.raw_offset, section.raw_size))
                        return section.rva_start.added(value.subtracted(section.raw_offset));
                }
                fail("MAPPING_NOT_FOUND", "file offset is not backed by an explicit section raw range");
            }

            calc_value evaluate_call(const std::string& name, const std::vector<calc_value>& arguments) const
            {
                if (name == "abs") {
                    require_count(name, arguments, 1, 1);
                    const bigint& value = integer_argument(name, arguments, 0);
                    const bigint normalized = options_.bit_width != 0 && options_.signed_result
                        ? bigint::from_twos_complement(value, options_.bit_width)
                        : value;
                    return integer_result(normalized.absolute());
                }
                if (name == "min" || name == "max") {
                    require_count(name, arguments, 2, 2);
                    const bigint& raw_left = integer_argument(name, arguments, 0);
                    const bigint& raw_right = integer_argument(name, arguments, 1);
                    const bigint left = options_.bit_width != 0 && options_.signed_result
                        ? bigint::from_twos_complement(raw_left, options_.bit_width)
                        : raw_left;
                    const bigint right = options_.bit_width != 0 && options_.signed_result
                        ? bigint::from_twos_complement(raw_right, options_.bit_width)
                        : raw_right;
                    const bool choose_left = name == "min" ? left.compare(right) <= 0 : left.compare(right) >= 0;
                    return integer_result(choose_left ? left : right);
                }
                if (name == "mask" || name == "bitmask") {
                    require_count(name, arguments, 1, 1);
                    const std::size_t bits = width_argument(name, arguments, 0, true);
                    return integer_result(bits == 0 ? bigint() : bigint::pow2(bits).subtracted(bigint::one()));
                }
                if (name == "truncate" || name == "trunc" || name == "zero_extend" || name == "zext" ||
                    name == "as_unsigned") {
                    require_count(name, arguments, 2, 2);
                    const std::size_t bits = width_argument(name, arguments, 1, true);
                    return integer_result(integer_argument(name, arguments, 0).unsigned_mod(bits));
                }
                if (name == "sign_extend" || name == "sext" || name == "as_signed") {
                    require_count(name, arguments, name == "as_signed" ? 2 : 2, name == "as_signed" ? 2 : 3);
                    const std::size_t source_bits = width_argument(name, arguments, 1);
                    if (arguments.size() == 3) {
                        const std::size_t target_bits = width_argument(name, arguments, 2);
                        if (target_bits < source_bits)
                            fail("RANGE_ERROR", "sign extension target width is smaller than source width");
                        return integer_result(
                            bigint::from_twos_complement(integer_argument(name, arguments, 0), source_bits).unsigned_mod(target_bits));
                    }
                    return integer_result(bigint::from_twos_complement(integer_argument(name, arguments, 0), source_bits));
                }
                if (name == "rotate_left" || name == "rol" || name == "rotate_right" || name == "ror") {
                    require_count(name, arguments, 2, 3);
                    const bigint& source = integer_argument(name, arguments, 0);
                    const std::size_t count = shift_amount(integer_argument(name, arguments, 1));
                    std::size_t width = options_.bit_width;
                    if (arguments.size() == 3)
                        width = width_argument(name, arguments, 2);
                    if (width == 0)
                        width = std::max<std::size_t>(1, source.bit_count());
                    const std::size_t rotation = count % width;
                    const bigint raw = source.unsigned_mod(width);
                    const bigint result = (name == "rotate_left" || name == "rol")
                        ? raw.shifted_left(rotation).unsigned_mod(width).added(raw.shifted_right_arithmetic(width - rotation)).unsigned_mod(width)
                        : raw.shifted_right_arithmetic(rotation).added(raw.shifted_left(width - rotation)).unsigned_mod(width);
                    return integer_result(result);
                }
                if (name == "align_up" || name == "align_down") {
                    require_count(name, arguments, 2, 2);
                    const bigint& value = integer_argument(name, arguments, 0);
                    const bigint& alignment = integer_argument(name, arguments, 1);
                    if (value.is_negative() || alignment.is_negative() || alignment.is_zero())
                        fail("RANGE_ERROR", "alignment operands must be non-negative and alignment non-zero");
                    const bigint remainder = bigint::divide_with_remainder(value, alignment).second;
                    if (name == "align_down" || remainder.is_zero())
                        return integer_result(value.subtracted(remainder));
                    return integer_result(value.added(alignment.subtracted(remainder)));
                }
                if (name == "endian_swap" || name == "byteswap" || name == "bswap") {
                    require_count(name, arguments, 1, 2);
                    const bigint& value = integer_argument(name, arguments, 0);
                    std::size_t byte_count = options_.bit_width == 0
                        ? std::max<std::size_t>(1, (value.bit_count() + 7) / 8)
                        : (options_.bit_width + 7) / 8;
                    if (arguments.size() == 2) {
                        const bigint& count = integer_argument(name, arguments, 1);
                        if (count.is_negative() || count.bit_count() > 63 || count.to_u64_checked() == 0 ||
                            count.to_u64_checked() > k_max_integer_bytes)
                            fail("RANGE_ERROR", "byte swap width must be between 1 and 8192 bytes");
                        byte_count = static_cast<std::size_t>(count.to_u64_checked());
                    }
                    std::vector<std::uint8_t> bytes = integer_to_bytes(value, byte_count, false);
                    std::reverse(bytes.begin(), bytes.end());
                    return integer_result(bytes_to_integer(bytes, false, false));
                }
                if (name == "bytes" || name == "hex_bytes") {
                    require_count(name, arguments, 1, 1);
                    if (arguments[0].kind != value_kind::text)
                        fail("TYPE_ERROR", name + " requires a hexadecimal string literal");
                    return calc_value::from_bytes(parse_hex_bytes(arguments[0].text));
                }
                if (name == "ascii") {
                    require_count(name, arguments, 1, 1);
                    if (arguments[0].kind != value_kind::text)
                        fail("TYPE_ERROR", "ascii requires a string literal");
                    const std::string& text = arguments[0].text;
                    if (!std::all_of(text.begin(), text.end(), [](char c) { return static_cast<unsigned char>(c) <= 0x7F; }))
                        fail("INVALID_ARGUMENT", "ascii string contains non-ASCII data");
                    return calc_value::from_bytes(std::vector<std::uint8_t>(text.begin(), text.end()));
                }
                if (name == "utf8") {
                    require_count(name, arguments, 1, 1);
                    if (arguments[0].kind != value_kind::text || !validate_utf8(arguments[0].text))
                        fail("INVALID_ARGUMENT", "utf8 requires a valid UTF-8 string literal");
                    return calc_value::from_bytes(std::vector<std::uint8_t>(arguments[0].text.begin(), arguments[0].text.end()));
                }
                if (name == "to_ascii" || name == "bytes_to_ascii") {
                    require_count(name, arguments, 1, 1);
                    const std::vector<std::uint8_t> bytes = explicit_bytes_argument(name, arguments, 0);
                    if (!std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) { return byte <= 0x7F; }))
                        fail("INVALID_ARGUMENT", "bytes cannot be represented as ASCII");
                    return calc_value::from_text(std::string(bytes.begin(), bytes.end()));
                }
                if (name == "to_utf8" || name == "bytes_to_utf8") {
                    require_count(name, arguments, 1, 1);
                    const std::vector<std::uint8_t> bytes = explicit_bytes_argument(name, arguments, 0);
                    const std::string text(bytes.begin(), bytes.end());
                    if (!validate_utf8(text))
                        fail("INVALID_ARGUMENT", "bytes cannot be represented as UTF-8");
                    return calc_value::from_text(text);
                }
                if (name == "int_to_bytes") {
                    require_count(name, arguments, 2, 3);
                    const bigint& value = integer_argument(name, arguments, 0);
                    const bigint& count = integer_argument(name, arguments, 1);
                    if (count.is_negative() || count.bit_count() > 63 || count.to_u64_checked() == 0 ||
                        count.to_u64_checked() > k_max_integer_bytes)
                        fail("RANGE_ERROR", "int_to_bytes count must be between 1 and 8192");
                    const bool big_endian = big_endian_argument(name, arguments, 2, false);
                    return calc_value::from_bytes(integer_to_bytes(value, static_cast<std::size_t>(count.to_u64_checked()), big_endian));
                }
                if (name == "bytes_to_int") {
                    require_count(name, arguments, 1, 3);
                    const std::vector<std::uint8_t> bytes = explicit_bytes_argument(name, arguments, 0);
                    const bool big_endian = big_endian_argument(name, arguments, 1, false);
                    const bool signed_value = boolean_argument(name, arguments, 2, false);
                    return integer_result(bytes_to_integer(bytes, big_endian, signed_value));
                }
                if (name == "crc32") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(bigint(crc32(explicit_bytes_argument(name, arguments, 0))));
                }
                if (name == "adler32") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(bigint(adler32(explicit_bytes_argument(name, arguments, 0))));
                }
                if (name == "fnv1a_32" || name == "fnv1a32") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(bigint(fnv1a32(explicit_bytes_argument(name, arguments, 0))));
                }
                if (name == "fnv1a_64" || name == "fnv1a64") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(bigint(fnv1a64(explicit_bytes_argument(name, arguments, 0))));
                }
                if (name == "float_to_bits")
                    return float_to_bits(name, arguments, 64);
                if (name == "float_bits" || name == "f32_to_bits" || name == "f32_bits")
                    return float_to_bits(name, arguments, 32);
                if (name == "double_bits" || name == "f64_to_bits" || name == "f64_bits")
                    return float_to_bits(name, arguments, 64);
                if (name == "bits_to_float")
                    return bits_to_float(name, arguments, 64);
                if (name == "bits_to_f32" || name == "bits_to_float32")
                    return bits_to_float(name, arguments, 32);
                if (name == "bits_to_double" || name == "bits_to_f64" || name == "bits_to_float64")
                    return bits_to_float(name, arguments, 64);
                if (name == "va_to_rva") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(va_to_rva(integer_argument(name, arguments, 0)));
                }
                if (name == "rva_to_va") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(rva_to_va(integer_argument(name, arguments, 0)));
                }
                if (name == "rva_to_file_offset") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(rva_to_file_offset(integer_argument(name, arguments, 0)));
                }
                if (name == "file_offset_to_rva") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(file_offset_to_rva(integer_argument(name, arguments, 0)));
                }
                if (name == "va_to_file_offset") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(rva_to_file_offset(va_to_rva(integer_argument(name, arguments, 0))));
                }
                if (name == "file_offset_to_va") {
                    require_count(name, arguments, 1, 1);
                    return integer_result(rva_to_va(file_offset_to_rva(integer_argument(name, arguments, 0))));
                }
                fail("UNKNOWN_FUNCTION", "unknown calculator function: " + name);
            }
        };

        std::string normalized_format(const std::string& format)
        {
            const std::string result = lower_ascii(format);
            if (result == "decimal" || result == "hex" || result == "binary" || result == "bin" ||
                result == "octal" || result == "oct" || result == "all")
                return result;
            fail("INVALID_ARGUMENT", "format must be decimal, hex, binary, octal, or all");
        }

        bigint display_integer(const bigint& value, const calculation_options_t& options)
        {
            if (options.bit_width != 0 && options.signed_result)
                return bigint::from_twos_complement(value, options.bit_width);
            return value;
        }

        json format_result(const calc_value& value, const calculation_options_t& options, const std::string& format)
        {
            const std::string selected_format = normalized_format(format);
            json result;
            if (value.kind == value_kind::integer) {
                const bigint display = display_integer(value.integer, options);
                const std::string decimal = display.to_decimal();
                const std::string hexadecimal = display.to_hexadecimal();
                const std::string binary = display.to_binary();
                const std::string octal = display.to_octal();
                result["type"] = "integer";
                result["bit_length"] = display.bit_count();
                if (options.bit_width != 0) {
                    result["width"] = options.bit_width;
                    result["signed"] = options.signed_result;
                }
                if (selected_format == "decimal" || selected_format == "all")
                    result["decimal"] = decimal;
                if (selected_format == "hex" || selected_format == "all")
                    result["hex"] = hexadecimal;
                if (selected_format == "binary" || selected_format == "bin" || selected_format == "all")
                    result["binary"] = binary;
                if (selected_format == "octal" || selected_format == "oct" || selected_format == "all")
                    result["octal"] = octal;
                if (selected_format == "decimal")
                    result["value"] = decimal;
                else if (selected_format == "hex")
                    result["value"] = hexadecimal;
                else if (selected_format == "binary" || selected_format == "bin")
                    result["value"] = binary;
                else if (selected_format == "octal" || selected_format == "oct")
                    result["value"] = octal;
                else
                    result["value"] = hexadecimal;
                return result;
            }
            if (value.kind == value_kind::bytes) {
                result["type"] = "bytes";
                result["value"] = hex_bytes(value.bytes);
                result["hex"] = result["value"];
                result["byte_length"] = value.bytes.size();
                if (printable_ascii(value.bytes))
                    result["ascii"] = std::string(value.bytes.begin(), value.bytes.end());
                const std::string utf8(value.bytes.begin(), value.bytes.end());
                if (validate_utf8(utf8))
                    result["utf8"] = utf8;
                return result;
            }
            if (value.kind == value_kind::text) {
                result["type"] = "text";
                result["value"] = value.text;
                result["byte_length"] = value.text.size();
                if (validate_utf8(value.text))
                    result["utf8"] = value.text;
                return result;
            }
            result["type"] = "float";
            result["value"] = floating_to_string(value.floating);
            result["width"] = value.floating_width;
            result["bits"] = value.floating_bits.to_hexadecimal();
            return result;
        }

        calc_result_t evaluate_expression(const calc_request_t& request, const environment_t& environment,
                                          calculation_options_t options, calculator_interrupt_t& interrupt)
        {
            calc_result_t result;
            result.id = request.id;
            try {
                interrupt.check_now();
                if (request.expression.empty())
                    fail("INVALID_ARGUMENT", "expression must not be empty");
                if (request.expression.size() > k_max_expression_bytes)
                    fail("LIMIT_EXCEEDED", "expression exceeds size limit");
                parser_t parser(request.expression, environment, options);
                const calc_value value = parser.parse();
                result.success = true;
                result.extra = format_result(value, options, request.format);
                if (value.kind == value_kind::integer) {
                    const bigint display = display_integer(value.integer, options);
                    result.value_decimal = display.to_decimal();
                    result.value_hex = display.to_hexadecimal();
                    result.value_binary = display.to_binary();
                    result.value_octal = display.to_octal();
                }
            } catch (const calc_error& error) {
                result.error = error.what();
                result.extra = {{"code", error.code()}};
            } catch (const std::exception& error) {
                result.error = error.what();
                result.extra = {{"code", "CALC_ERROR"}};
            }
            return result;
        }

        json item_json(const calc_result_t& result, bool include_id)
        {
            json output;
            if (include_id)
                output["id"] = result.id;
            output["success"] = result.success;
            if (result.success) {
                output["result"] = result.extra;
            } else {
                output["error"] = {{"code", result.extra.value("code", std::string("CALC_ERROR"))}, {"message", result.error}};
            }
            return output;
        }

        calc_request_t parse_request(const json& object, const std::string& default_format)
        {
            if (!object.is_object())
                fail("INVALID_ARGUMENT", "calculation item must be an object");
            calc_request_t request;
            if (object.contains("id")) {
                if (!object.at("id").is_string())
                    fail("INVALID_ARGUMENT", "calculation item id must be a string");
                request.id = object.at("id").get<std::string>();
            }
            if (!object.contains("expression") || !object.at("expression").is_string())
                fail("INVALID_ARGUMENT", "calculation item expression must be a string");
            request.expression = object.at("expression").get<std::string>();
            request.format = default_format;
            if (object.contains("format")) {
                if (!object.at("format").is_string())
                    fail("INVALID_ARGUMENT", "calculation format must be a string");
                request.format = object.at("format").get<std::string>();
            }
            request.format = normalized_format(request.format);
            return request;
        }
    }

    tool_result_t calculate_engine(const json& params, const workspace_request_context_t& context)
    {
        calculator_interrupt_t interrupt(context);
        interrupt_scope_t scope(interrupt);
        try {
            interrupt.check_now();
            if (!params.is_object())
                return tool_result_t::error("calculator parameters must be an object", std::string("INVALID_ARGUMENT"));
            calculation_options_t global_options = parse_options(params);
            const std::string default_format = normalized_format(params.value("format", std::string("hex")));
            environment_t environment;
            if (params.contains("variables"))
                add_variables(environment, params.at("variables"));
            if (params.contains("mapping"))
                environment.mapping = parse_mapping(params.at("mapping"));

            if (params.contains("items")) {
                json single_item_batch;
                const json* items_ptr = &params.at("items");
                if (params.at("items").is_object()) {
                    single_item_batch = json::array({params.at("items")});
                    items_ptr = &single_item_batch;
                } else if (!params.at("items").is_array()) {
                    return tool_result_t::error("items must be an object or array", std::string("INVALID_ARGUMENT"));
                }
                const json& items = *items_ptr;
                if (items.empty())
                    return tool_result_t::error("items must not be empty", std::string("INVALID_ARGUMENT"));
                if (items.size() > CALC_MAX_ITEMS)
                    return tool_result_t::error("too many items (max 128)", std::string("LIMIT_EXCEEDED"));
                json results = json::array();
                bool interrupted = false;
                for (const json& item : items) {
                    calc_result_t result;
                    try {
                        if (interrupted)
                            fail("CANCELLED", "calculator request cancelled");
                        interrupt.check_now();
                        const calculation_options_t options = parse_options(item, global_options);
                        const calc_request_t request = parse_request(item, default_format);
                        environment_t item_environment = environment;
                        if (item.contains("variables"))
                            add_variables(item_environment, item.at("variables"));
                        if (item.contains("mapping"))
                            item_environment.mapping = parse_mapping(item.at("mapping"));
                        result = evaluate_expression(request, item_environment, options, interrupt);
                        if (!result.success) {
                            const std::string code = result.extra.value("code", std::string("CALC_ERROR"));
                            interrupted = code == "CANCELLED" || code == "DEADLINE_EXCEEDED";
                        }
                    } catch (const calc_error& error) {
                        result.success = false;
                        result.error = error.what();
                        result.extra = {{"code", error.code()}};
                        interrupted = error.code() == "CANCELLED" || error.code() == "DEADLINE_EXCEEDED";
                    } catch (const std::exception& error) {
                        result.success = false;
                        result.error = error.what();
                        result.extra = {{"code", "CALC_ERROR"}};
                    }
                    if (item.is_object() && item.contains("id") && item.at("id").is_string())
                        result.id = item.at("id").get<std::string>();
                    results.push_back(item_json(result, !result.id.empty()));
                }
                return tool_result_t::ok({{"results", results}, {"count", results.size()}});
            }

            const calc_request_t request = parse_request(params, default_format);
            const calc_result_t result = evaluate_expression(request, environment, global_options, interrupt);
            if (!result.success)
                return tool_result_t::error(result.error, result.extra.value("code", std::string("CALC_ERROR")));
            return tool_result_t::ok(result.extra);
        } catch (const calc_error& error) {
            return tool_result_t::error(error.what(), error.code());
        } catch (const std::exception& error) {
            return tool_result_t::error(error.what(), std::string("CALC_ERROR"));
        }
    }

}
