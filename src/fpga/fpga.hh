#pragma once

#include <cstdint>
#include <memory>

#include "src/detail/backend.hh"

namespace volk::dma::fpga {

using VmmHandle = std::shared_ptr<tdVMM_HANDLE>;

[[nodiscard]] std::shared_ptr<detail::DeviceBackend> open_device(bool use_memory_map);
[[nodiscard]] std::shared_ptr<detail::ProcessBackend> open_process(VmmHandle vmm, uint32_t process_id);
[[nodiscard]] std::unique_ptr<detail::ScatterBackend> open_scatter(VmmHandle vmm, uint32_t process_id);
[[nodiscard]] std::unique_ptr<detail::InputBackend> open_input(const Device& device, VMM_HANDLE vmm);

} // namespace volk::dma::fpga
