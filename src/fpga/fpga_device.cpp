#include "src/fpga/fpga.hh"

#include <VolkLog/log.hh>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

#include "external/vmm/vmmdll.h"

#include "src/fpga/resource.hh"

namespace volk::dma::fpga {

namespace {

constexpr volk::log::Logger logger{ "dma.device" };

constexpr auto vmm_close = [](VMM_HANDLE handle) noexcept {
    if (handle) VMMDLL_Close(handle);
};

bool dump_memory_map() {
    LPCSTR argv[] = { "-device", "fpga", "-waitinitialize", "-norefresh" };
    const DWORD argc = static_cast<DWORD>(std::size(argv));

    const std::unique_ptr<tdVMM_HANDLE, decltype(vmm_close)> temp_handle(VMMDLL_Initialize(argc, argv));
    if (!temp_handle) {
        logger.error("Failed to open handle.");
        return false;
    }

    detail::Resource<VMMDLL_MAP_PHYSMEM> p_phys_mem_map{};
    if (!VMMDLL_Map_GetPhysMem(temp_handle.get(), p_phys_mem_map.out())) {
        logger.error("Failed to get physical memory map.");
        return false;
    }

    if (!p_phys_mem_map ||
        p_phys_mem_map->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION ||
        p_phys_mem_map->cMap == 0) {
        logger.error("Invalid memory map.");
        return false;
    }

    std::stringstream sb;
    for (DWORD i = 0; i < p_phys_mem_map->cMap; ++i) {
        sb << std::hex << p_phys_mem_map->pMap[i].pa << " " << (p_phys_mem_map->pMap[i].pa + p_phys_mem_map->pMap[i].cb - 1) << std::endl;
    }

    auto current_path = std::filesystem::current_path();
    std::ofstream file(current_path / "memory_map.txt");
    if (!file.is_open()) {
        return false;
    }

    file << sb.str();
    file.close();

    return true;
}

bool clean_fpga(VMM_HANDLE vmm) {
    ULONG64 fpga_id = 0, version_major = 0, version_minor = 0;

    if (!(VMMDLL_ConfigGet(vmm, LC_OPT_FPGA_FPGA_ID, &fpga_id) && VMMDLL_ConfigGet(vmm, LC_OPT_FPGA_VERSION_MAJOR, &version_major) && VMMDLL_ConfigGet(vmm, LC_OPT_FPGA_VERSION_MINOR, &version_minor))) {
        logger.warn("Failed to lookup FPGA device, attempting to continue initializing.");
        return false;
    }

    if ((version_major >= 4) && ((version_major >= 5) || (version_minor >= 7))) {
        LC_CONFIG config{ .dwVersion = LC_CONFIG_VERSION, .szDevice = "existing" };
        HANDLE lc_handle = LcCreate(&config);

        if (!lc_handle) {
            logger.warn("Failed to create FPGA device handle, attempting to continue initializing.");
            return false;
        }

        static const unsigned char abort_2[4] = { 0x10, 0x00, 0x10, 0x00 };
        LcCommand(lc_handle, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, sizeof(abort_2), const_cast<unsigned char*>(abort_2), NULL, NULL);
        LcClose(lc_handle);
    }

    return true;
}

class FpgaDevice final : public detail::DeviceBackend {
public:
    explicit FpgaDevice(VmmHandle vmm) : vmm(std::move(vmm)) {}

    VMM_HANDLE vmm_handle() const noexcept override {
        return vmm.get();
    }

    std::optional<uint32_t> process_id(const std::string& process_name) const override {
        DWORD process_id = 0;
        if (!VMMDLL_PidGetFromName(vmm.get(), process_name.c_str(), &process_id) || process_id == 0) {
            return std::nullopt;
        }

        return process_id;
    }

    std::vector<uint32_t> process_ids(const std::string& process_name) const override {
        std::vector<uint32_t> list = { };

        detail::Resource<VMMDLL_PROCESS_INFORMATION> process_info{};
        DWORD total_processes = 0;

        if (!VMMDLL_ProcessGetInformationAll(vmm.get(), process_info.out(), &total_processes) || total_processes == 0) {
            logger.error("Failed to retrieve process list.");
            return list;
        }

        for (size_t i = 0; i < total_processes; i++) {
            const auto& process = process_info.get()[i];
            if (strstr(process.szNameLong, process_name.c_str())) {
                list.push_back(process.dwPID);
            }
        }

        return list;
    }

    std::shared_ptr<detail::ProcessBackend> open_process(uint32_t process_id) const override {
        return fpga::open_process(vmm, process_id);
    }

    std::unique_ptr<detail::InputBackend> create_input(const Device& device) const override {
        return open_input(device, vmm.get());
    }

private:
    VmmHandle vmm;
};

} // namespace

std::shared_ptr<detail::DeviceBackend> open_device(bool use_memory_map) {
    LPCSTR argv[8] = {"", "-device", "fpga://algo=0", "", "", "", "", ""};
    DWORD argc = 3;

    std::string path;
    if (use_memory_map) {
        path = (std::filesystem::current_path() / "memory_map.txt").string();

        if (!std::filesystem::exists(path) && !dump_memory_map()) {
            logger.warn("Could not dump memory map.");
        }
        else {
            argv[argc++] = "-memmap";
            argv[argc++] = path.c_str();
        }
    }

    VmmHandle vmm(VMMDLL_Initialize(argc, argv), vmm_close);
    if (!vmm) {
        logger.error("Failed to initialize.");
        return nullptr;
    }

    clean_fpga(vmm.get());

    return std::make_shared<FpgaDevice>(std::move(vmm));
}

} // namespace volk::dma::fpga
