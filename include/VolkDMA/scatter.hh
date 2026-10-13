#pragma once

#include <cstdint>
#include <type_traits>
#include <vector>

struct tdVMM_HANDLE;
using VMM_HANDLE = tdVMM_HANDLE*;
using VMMDLL_SCATTER_HANDLE = void*;

namespace volk::dma {

class Process;

class Scatter {
public:
    ~Scatter();

    Scatter(const Scatter&) = delete;
    Scatter& operator=(const Scatter&) = delete;
    Scatter(Scatter&& other) noexcept;

    bool prepare_read(uint64_t address, void* buffer, size_t size);
    bool prepare_write(uint64_t address, const void* buffer, size_t size);
    bool execute();

    template <typename T>
    bool prepare_read(uint64_t address, T* buffer) {
        return this->prepare_read(address, reinterpret_cast<void*>(buffer), sizeof(T));
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    bool prepare_read(uint64_t address, std::vector<T>& buffer, size_t count) {
        buffer.resize(count);
        if (count == 0) return false;
        return this->prepare_read(address, buffer.data(), count * sizeof(T));
    }

    template <typename T>
    bool prepare_write(uint64_t address, const T& value) {
        return this->prepare_write(address, &value, sizeof(T));
    }

private:
    friend class Process;
    Scatter(VMM_HANDLE vmm, uint32_t process_id);

    uint32_t process_id;
    VMMDLL_SCATTER_HANDLE handle{};
    int pending_count{};
};

} // namespace volk::dma
