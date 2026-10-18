#include "src/fpga/fpga.hh"

#include <VolkLog/log.hh>

#include <cstring>
#include <utility>

#include "external/vmm/vmmdll.h"

namespace volk::dma::fpga {

namespace {

constexpr volk::log::Logger logger{ "dma.scatter" };

constexpr DWORD scatter_flags = VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO;

class FpgaScatter final : public detail::ScatterBackend {
public:
    FpgaScatter(VmmHandle vmm, uint32_t process_id) : vmm(std::move(vmm)), process_id(process_id) {
        handle = VMMDLL_Scatter_Initialize(this->vmm.get(), process_id, scatter_flags);
        if (!handle) {
            logger.error("Failed to create handle.");
        }
    }

    ~FpgaScatter() override {
        if (handle) {
            VMMDLL_Scatter_CloseHandle(handle);
        }
    }

    FpgaScatter(const FpgaScatter&) = delete;
    FpgaScatter& operator=(const FpgaScatter&) = delete;

    bool prepare_read(uint64_t address, void* buffer, size_t size) override {
        if (!VMMDLL_Scatter_PrepareEx(handle, address, static_cast<DWORD>(size), static_cast<PBYTE>(buffer), NULL)) {
            logger.error("Failed to prepare read at 0x{:x}.", address);
            std::memset(buffer, 0, size);
            return false;
        }
        ++pending_count;

        return true;
    }

    bool prepare_write(uint64_t address, const void* buffer, size_t size) override {
        if (!VMMDLL_Scatter_PrepareWrite(handle, address, static_cast<PBYTE>(const_cast<void*>(buffer)), static_cast<DWORD>(size))) {
            logger.error("Failed to prepare write at 0x{:x}.", address);
            return false;
        }
        ++pending_count;

        return true;
    }

    bool execute() override {
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

private:
    VmmHandle vmm;
    uint32_t process_id;
    VMMDLL_SCATTER_HANDLE handle{};
    int pending_count{};
};

} // namespace

std::unique_ptr<detail::ScatterBackend> open_scatter(VmmHandle vmm, uint32_t process_id) {
    return std::make_unique<FpgaScatter>(std::move(vmm), process_id);
}

} // namespace volk::dma::fpga
