#pragma once

#include <cstdint>
#include <memory>
#include <type_traits>
#include <vector>

#include "profiler.hh"

namespace volk::dma {

class Process;

namespace detail {

class ScatterBackend;

} // namespace detail

class Scatter {
public:
    ~Scatter();

    Scatter(const Scatter&) = delete;
    Scatter& operator=(const Scatter&) = delete;
    Scatter(Scatter&& other) noexcept;

    bool prepare_read(uint64_t address, void* buffer, size_t size);
    bool prepare_write(uint64_t address, const void* buffer, size_t size);
    bool execute(profiler::Location caller = profiler::Location::current(), profiler::Location origin = {});

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

    explicit Scatter(std::unique_ptr<detail::ScatterBackend> backend);

    std::unique_ptr<detail::ScatterBackend> backend;
};

} // namespace volk::dma
