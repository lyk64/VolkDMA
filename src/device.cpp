#include "include/VolkDMA/device.hh"

#include <utility>

#include "detail/backend.hh"
#include "fpga/fpga.hh"

#ifdef VOLKDMA_LOCAL_BACKEND
#include "local/local.hh"
#endif

namespace volk::dma {

namespace {

std::shared_ptr<detail::DeviceBackend> open_local_device() {
#ifdef VOLKDMA_LOCAL_BACKEND
    return local::open_device();
#else
    return nullptr;
#endif
}

} // namespace

std::expected<Device, OpenError> Device::open(const DeviceOptions& options) {
    switch (options.backend) {
    case Backend::fpga:
        if (auto backend = fpga::open_device(options.use_memory_map)) {
            return Device{ std::move(backend) };
        }
        return std::unexpected(OpenError::initialization_failed);

    case Backend::local:
        if (auto backend = open_local_device()) {
            return Device{ std::move(backend) };
        }
        return std::unexpected(OpenError::backend_unavailable);
    }

    return std::unexpected(OpenError::backend_unavailable);
}

Device::Device(std::shared_ptr<detail::DeviceBackend> backend) : backend(std::move(backend)) {}

VMM_HANDLE Device::get_handle() const noexcept {
    return backend->vmm_handle();
}

std::optional<uint32_t> Device::get_process_id(const std::string& process_name) const {
    return backend->process_id(process_name);
}

std::vector<uint32_t> Device::get_process_id_list(const std::string& process_name) const {
    return backend->process_ids(process_name);
}

} // namespace volk::dma
