#include "include/VolkDMA/scatter.hh"

#include <cstring>
#include <utility>

#include "include/VolkDMA/address.hh"
#include "detail/backend.hh"

namespace volk::dma {

Scatter::Scatter(std::unique_ptr<detail::ScatterBackend> backend) : backend(std::move(backend)) {}

Scatter::~Scatter() = default;

Scatter::Scatter(Scatter&& other) noexcept = default;

bool Scatter::prepare_read(uint64_t address, void* buffer, size_t size) {
    if (!is_valid_address(address)) {
        std::memset(buffer, 0, size);
        return false;
    }

    return backend->prepare_read(address, buffer, size);
}

bool Scatter::prepare_write(uint64_t address, const void* buffer, size_t size) {
    if (!is_valid_address(address)) {
        return false;
    }

    return backend->prepare_write(address, buffer, size);
}

bool Scatter::execute(profiler::Location caller, profiler::Location origin) {
    const profiler::Timed timed{ caller, origin };
    return backend->execute();
}

} // namespace volk::dma
