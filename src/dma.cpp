#include "include/VolkDMA/dma.hh"

#include <VolkLog/log.hh>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/inputstate.hh"
#include "include/VolkDMA/internal/volkresource.hh"

static constexpr Volk::Log::Logger logger{ "DMA" };

template<typename T>
T DMA::read(uint64_t address, DWORD process_id) const {
    T rdbuf = {};
    VMMDLL_MemReadEx(this->handle.get(), process_id, address,
        reinterpret_cast<PBYTE>(&rdbuf),
        sizeof(T), nullptr,
        VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
    return rdbuf;
}

template uint64_t DMA::read<uint64_t>(uint64_t, DWORD) const;
template uint32_t DMA::read<uint32_t>(uint64_t, DWORD) const;
template int DMA::read<int>(uint64_t, DWORD) const;
template InputState::Point DMA::read<InputState::Point>(uint64_t, DWORD) const;

DMA::DMA(bool use_memory_map) {
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

    handle.reset(VMMDLL_Initialize(argc, argv));
    if (!handle) {
        logger.error("Failed to initialize.");
        return;
    }

    this->clean_fpga();
}

DWORD DMA::get_process_id(const std::string& process_name) const {
    DWORD process_id = 0;

    if (!VMMDLL_PidGetFromName(this->handle.get(), process_name.c_str(), &process_id) || process_id == 0) {
        logger.error("Failed to get ID for process: {}.", process_name);
    }

    return process_id;
}

std::vector<DWORD> DMA::get_process_id_list(const std::string& process_name) const {
    std::vector<DWORD> list = { };

    VolkResource<VMMDLL_PROCESS_INFORMATION> process_info{};
    DWORD total_processes = 0;

    if (!VMMDLL_ProcessGetInformationAll(this->handle.get(), process_info.out(), &total_processes) || total_processes == 0) {
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

uint64_t DMA::find_signature(const char* signature, uint64_t range_start, uint64_t range_end, DWORD process_id) const {
    if (!signature || !*signature || range_start >= range_end) {
        return 0;
    }

    uint64_t size = range_end - range_start;
    std::vector<uint8_t> buffer(size);

    if (!VMMDLL_MemReadEx(this->handle.get(), process_id, range_start, buffer.data(), size, nullptr, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
        return 0;
    }

    const char* pat = signature;
    uint64_t first_match = 0;

    auto get_byte = [](const char* hex) -> uint8_t {
        char byte[3] = { hex[0], hex[1], 0 };
        return static_cast<uint8_t>(std::strtoul(byte, nullptr, 16));
    };

    for (uint64_t i = 0; i < size; i++) {
        if (*pat == '\0') {
            break;
        }

        if (*pat == '?' || buffer[i] == get_byte(pat)) {
            if (!first_match) {
                first_match = range_start + i;
            }

            pat += (*pat == '?') ? 2 : 3;

            if (*pat == '\0') {
                return first_match;
            }
        }
        else {
            pat = signature;
            first_match = 0;
        }
    }

    return 0;
}

bool DMA::dump_memory_map() {
    LPCSTR argv[] = { "-device", "fpga", "-waitinitialize", "-norefresh" };
    const DWORD argc = static_cast<DWORD>(std::size(argv));

    VolkHandle temp_handle(VMMDLL_Initialize(argc, argv), vmm_close);
    if (!temp_handle) {
        logger.error("Failed to open handle.");
        return false;
    }

    VolkResource<VMMDLL_MAP_PHYSMEM> p_phys_mem_map{};
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

bool DMA::clean_fpga() {
    ULONG64 fpga_id = 0, version_major = 0, version_minor = 0;

    if (!(VMMDLL_ConfigGet(this->handle.get(), LC_OPT_FPGA_FPGA_ID, &fpga_id) && VMMDLL_ConfigGet(this->handle.get(), LC_OPT_FPGA_VERSION_MAJOR, &version_major) && VMMDLL_ConfigGet(this->handle.get(), LC_OPT_FPGA_VERSION_MINOR, &version_minor))) {
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