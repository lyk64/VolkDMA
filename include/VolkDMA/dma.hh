#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

struct tdVMM_HANDLE;
using VMM_HANDLE = tdVMM_HANDLE*;

extern "C" void VMMDLL_Close(VMM_HANDLE);

namespace volk::dma {

namespace detail {

inline constexpr auto vmm_close = [](VMM_HANDLE h) noexcept { if (h) VMMDLL_Close(h); };
using VmmHandle = std::unique_ptr<std::remove_pointer_t<VMM_HANDLE>, decltype(vmm_close)>;

} // namespace detail

class Device {
public:
    explicit Device(bool use_memory_map = true);

    [[nodiscard]] VMM_HANDLE get_handle() const noexcept { return handle.get(); }

    [[nodiscard]] uint32_t get_process_id(const std::string& process_name) const;
    [[nodiscard]] std::vector<uint32_t> get_process_id_list(const std::string& process_name) const;

private:
    detail::VmmHandle handle{};
    bool dump_memory_map();
    bool clean_fpga();
};

} // namespace volk::dma
