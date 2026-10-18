#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <windows.h>

#include "src/detail/backend.hh"

namespace volk::dma::local {

struct HandleCloser {
    void operator()(HANDLE handle) const noexcept {
        if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
};

using UniqueHandle = std::unique_ptr<void, HandleCloser>;
using ProcessHandle = std::shared_ptr<void>;

[[nodiscard]] std::wstring widen(std::string_view text);
[[nodiscard]] std::string narrow(std::wstring_view text);

[[nodiscard]] std::shared_ptr<detail::DeviceBackend> open_device();
[[nodiscard]] std::shared_ptr<detail::ProcessBackend> open_process(uint32_t process_id);
[[nodiscard]] std::unique_ptr<detail::ScatterBackend> open_scatter(ProcessHandle process, uint32_t process_id);
[[nodiscard]] std::unique_ptr<detail::InputBackend> open_input();

} // namespace volk::dma::local
