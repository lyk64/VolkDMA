#pragma once

#include <cstdint>
#include <type_traits>
#include <vector>

class DMA;
using VMMDLL_SCATTER_HANDLE = void*;

class Scatter {
public:
    Scatter(const DMA& dma, uint32_t process_id);
    ~Scatter();

    Scatter(const Scatter&) = delete;
    Scatter& operator=(const Scatter&) = delete;
    Scatter(Scatter&& other) noexcept;

    [[nodiscard]] bool is_valid_address(uint64_t address) const noexcept { return address >= 0x1000; }

    bool read(uint64_t address, void* buffer, size_t size);
    bool write(uint64_t address, const void* buffer, size_t size);
    bool execute();

    template <typename T>
    bool read(uint64_t address, T* buffer) {
        return this->read(address, reinterpret_cast<void*>(buffer), sizeof(T));
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    bool read(uint64_t address, std::vector<T>& buffer, size_t count) {
        buffer.resize(count);
        if (count == 0) return false;
        return this->read(address, buffer.data(), count * sizeof(T));
    }

    template <typename T>
    bool write(uint64_t address, const T& value) {
        return this->write(address, &value, sizeof(T));
    }

private:
    uint32_t process_id;
    VMMDLL_SCATTER_HANDLE handle{};
    int pending_count{};
};
