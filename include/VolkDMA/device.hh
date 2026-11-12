#pragma once

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct tdVMM_HANDLE;
using VMM_HANDLE = tdVMM_HANDLE*;

namespace volk::dma {

namespace detail {

class DeviceBackend;
class SessionRefresh;

} // namespace detail

enum class Backend {
    fpga,
    local,
};

struct DeviceOptions {
    Backend backend = Backend::fpga;
    bool use_memory_map = true;
};

enum class OpenError {
    initialization_failed,
    backend_unavailable,
};

[[nodiscard]] constexpr std::string_view to_string(OpenError error) noexcept {
    switch (error) {
    case OpenError::initialization_failed: return "initialization failed";
    case OpenError::backend_unavailable: return "backend not available in this build";
    }
    return "unknown";
}

class Device {
public:
    [[nodiscard]] static std::expected<Device, OpenError> open(const DeviceOptions& options = {});

    [[nodiscard]] VMM_HANDLE get_handle() const noexcept;

    [[nodiscard]] std::optional<uint32_t> get_process_id(const std::string& process_name) const;
    [[nodiscard]] std::vector<uint32_t> get_process_id_list(const std::string& process_name) const;

private:
    friend class Process;
    friend class InputState;
    friend class detail::SessionRefresh;

    explicit Device(std::shared_ptr<detail::DeviceBackend> backend);

    std::shared_ptr<detail::DeviceBackend> backend;
};

} // namespace volk::dma
