#include "include/VolkDMA/device.hh"

#include <utility>

#include "detail/backend.hh"
#include "fpga/fpga.hh"

namespace volk::dma {

std::optional<Device> Device::open(bool use_memory_map) {
    auto backend = fpga::open_device(use_memory_map);
    if (!backend) {
        return std::nullopt;
    }

    return Device{ std::move(backend) };
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
