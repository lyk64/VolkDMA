#pragma once

#include <cstdint>

namespace volk::dma {

inline constexpr uint64_t lowest_user_address = 0x10000;

[[nodiscard]] inline constexpr bool is_user_address(uint64_t address) noexcept {
    return address >= lowest_user_address && (address >> 47) == 0;
}

[[nodiscard]] inline constexpr bool is_kernel_address(uint64_t address) noexcept {
    return (address >> 47) == 0x1FFFFULL;
}

[[nodiscard]] inline constexpr bool is_valid_address(uint64_t address) noexcept {
    return is_user_address(address) || is_kernel_address(address);
}

} // namespace volk::dma
