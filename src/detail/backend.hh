#pragma once

#include <bitset>
#include <cstdint>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

#include "include/VolkDMA/inputstate.hh"

struct tdVMM_HANDLE;
using VMM_HANDLE = tdVMM_HANDLE*;

namespace volk::dma {

class Device;

namespace detail {

struct ModuleInfo {
    uint64_t base{};
    size_t size{};
    std::string path;
};

class ScatterBackend {
public:
    virtual ~ScatterBackend() = default;

    virtual bool prepare_read(uint64_t address, void* buffer, size_t size) = 0;
    virtual bool prepare_write(uint64_t address, const void* buffer, size_t size) = 0;
    virtual bool execute() = 0;
};

class ProcessBackend {
public:
    virtual ~ProcessBackend() = default;

    [[nodiscard]] virtual std::optional<size_t> read(uint64_t address, void* buffer, size_t size) const = 0;
    [[nodiscard]] virtual bool write(uint32_t process_id, uint64_t address, const void* buffer, size_t size) const = 0;
    [[nodiscard]] virtual std::optional<ModuleInfo> module(const std::string& module_name) const = 0;
    [[nodiscard]] virtual uint64_t export_address(const std::string& module_name, const std::string& export_name) const = 0;
    [[nodiscard]] virtual std::optional<std::vector<std::string>> modules(uint32_t process_id) const = 0;
    [[nodiscard]] virtual bool fix_cr3(const std::string& module_name, std::stop_token stop_token) = 0;
    [[nodiscard]] virtual std::unique_ptr<ScatterBackend> create_scatter(uint32_t process_id) const = 0;
};

class InputBackend {
public:
    virtual ~InputBackend() = default;

    [[nodiscard]] virtual InputState::Point cursor_position() const = 0;
    [[nodiscard]] virtual std::optional<std::bitset<256>> read_keys() const = 0;
};

class DeviceBackend {
public:
    virtual ~DeviceBackend() = default;

    [[nodiscard]] virtual VMM_HANDLE vmm_handle() const noexcept = 0;
    [[nodiscard]] virtual std::optional<uint32_t> process_id(const std::string& process_name) const = 0;
    [[nodiscard]] virtual std::vector<uint32_t> process_ids(const std::string& process_name) const = 0;
    [[nodiscard]] virtual std::shared_ptr<ProcessBackend> open_process(uint32_t process_id) const = 0;
    [[nodiscard]] virtual std::unique_ptr<InputBackend> create_input(const Device& device) const = 0;
};

} // namespace detail

} // namespace volk::dma
