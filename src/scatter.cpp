#include "include/VolkDMA/scatter.hh"

#include <VolkLog/log.hh>

#include <cstring>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/address.hh"
#include "include/VolkDMA/dma.hh"

namespace volk::dma {

static constexpr Volk::Log::Logger logger{ "SCATTER" };

static constexpr DWORD scatter_flags = VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO;

Scatter::Scatter(const Device& dma, uint32_t process_id) : process_id(process_id) {
    handle = VMMDLL_Scatter_Initialize(dma.get_handle(), process_id, scatter_flags);
    if (!handle) {
        logger.error("Failed to create handle.");
    }
}

Scatter::~Scatter() {
    if (handle) {
        VMMDLL_Scatter_CloseHandle(handle);
    }
}

Scatter::Scatter(Scatter&& other) noexcept : process_id(other.process_id), handle(other.handle), pending_count(other.pending_count) {
    other.handle = nullptr;
    other.pending_count = 0;
}

bool Scatter::prepare_read(uint64_t address, void* buffer, size_t size) {
    if (!is_valid_address(address)) {
        std::memset(buffer, 0, size);
        return false;
    }

    if (!VMMDLL_Scatter_PrepareEx(handle, address, static_cast<DWORD>(size), static_cast<PBYTE>(buffer), NULL)) {
        logger.error("Failed to prepare read at 0x{:x}.", address);
        std::memset(buffer, 0, size);
        return false;
    }
    ++pending_count;

    return true;
}

bool Scatter::prepare_write(uint64_t address, const void* buffer, size_t size) {
    if (!is_valid_address(address)) {
        return false;
    }

    if (!VMMDLL_Scatter_PrepareWrite(handle, address, static_cast<PBYTE>(const_cast<void*>(buffer)), static_cast<DWORD>(size))) {
        logger.error("Failed to prepare write at 0x{:x}.", address);
        return false;
    }
    ++pending_count;

    return true;
}

bool Scatter::execute() {
    if (pending_count == 0) {
        return true;
    }

    bool success = true;

    if (!VMMDLL_Scatter_Execute(handle)) {
        logger.error("Failed to execute.");
        success = false;
    }

    if (!VMMDLL_Scatter_Clear(handle, process_id, scatter_flags)) {
        logger.error("Failed to clear.");
        success = false;
    }

    pending_count = 0;

    return success;
}

} // namespace volk::dma
