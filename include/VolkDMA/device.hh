#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct tdVMM_HANDLE;
using VMM_HANDLE = tdVMM_HANDLE*;

namespace volk::dma {

namespace detail {

class DeviceBackend;

} // namespace detail

class Device {
public:
    [[nodiscard]] static std::optional<Device> open(bool use_memory_map = true);

    [[nodiscard]] VMM_HANDLE get_handle() const noexcept;

    [[nodiscard]] std::optional<uint32_t> get_process_id(const std::string& process_name) const;
    [[nodiscard]] std::vector<uint32_t> get_process_id_list(const std::string& process_name) const;

private:
    friend class Process;
    friend class InputState;

    explicit Device(std::shared_ptr<detail::DeviceBackend> backend);

    std::shared_ptr<detail::DeviceBackend> backend;
};

} // namespace volk::dma
