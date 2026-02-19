#include "include/VolkDMA/process.hh"

#include <VolkLog/log.hh>

#include <cstring>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/dma.hh"
#include "include/VolkDMA/internal/volkresource.hh"

static constexpr Volk::Log::Logger logger{ "PROCESS" };

static constexpr DWORD scatter_flags = VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_SCATTER_PREPAREEX_NOMEMZERO;

static uint64_t cb_size = 0x80000;
VOID cb_add_file(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo) {
    if (strcmp(uszName, "dtb.txt") == 0)
        cb_size = cb;
}

Process::Process(DMA& dma, const std::string& process_name) : dma(dma), process_id(dma.get_process_id(process_name)) {}

uint64_t Process::get_base_address(const std::string& module_name) const {
    VolkResource<VMMDLL_MAP_MODULEENTRY> module_entry{};

    if (!VMMDLL_Map_GetModuleFromNameU(this->dma.handle.get(), this->process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find base address of module: {}.", module_name);
        return 0;
    }

    return static_cast<uint64_t>(module_entry->vaBase);
}

size_t Process::get_size(const std::string& module_name) const {
    VolkResource<VMMDLL_MAP_MODULEENTRY> module_entry{};

    if (!VMMDLL_Map_GetModuleFromNameU(this->dma.handle.get(), this->process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find size of module: {}.", module_name);
        return 0;
    }

    return static_cast<size_t>(module_entry->cbImageSize);
}

bool Process::dump_module(const std::string& module_name, const std::string& path) const {
    const uint64_t base_address = this->get_base_address(module_name);
    if (!base_address) {
        logger.error("Failed to get base address for module: {}.", module_name);
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    if (!read(base_address, &dos, sizeof(IMAGE_DOS_HEADER))) {
        logger.error("Failed to read IMAGE_DOS_HEADER for module: {}.", module_name);
        return false;
    }

    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        logger.error("Invalid DOS signature for module: {}.", module_name);
        return false;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!this->read(base_address + dos.e_lfanew, &nt, sizeof(nt))) {
        logger.error("Failed to read IMAGE_NT_HEADERS64 for module: {}.", module_name);
        return false;
    }

    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        logger.error("Invalid NT headers for module: {}.", module_name);
        return false;
    }

    const size_t image_size = nt.OptionalHeader.SizeOfImage;
    auto image_buffer = std::make_unique<uint8_t[]>(image_size);

    this->read(base_address, image_buffer.get(), image_size);
    auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(image_buffer.get() + dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader);

    for (size_t i = 0; i < nt.FileHeader.NumberOfSections; i++, section_header++) {
        section_header->PointerToRawData = section_header->VirtualAddress;
        section_header->SizeOfRawData = section_header->Misc.VirtualSize;
    }

    HANDLE file_handle = CreateFileW(std::wstring(path.begin(), path.end()).c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_COMPRESSED, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    BOOL success = WriteFile(file_handle, image_buffer.get(), static_cast<DWORD>(image_size), &written, nullptr);
    CloseHandle(file_handle);

    if (!success || written != image_size) {
        logger.error("Failed to write dump for module: {}.", module_name);
        return false;
    }

    return true;
}

std::string Process::get_path(const std::string& module_name) const {
    VolkResource<VMMDLL_MAP_MODULEENTRY> mod;

    if (!VMMDLL_Map_GetModuleFromNameU(this->dma.handle.get(), this->process_id, module_name.c_str(), mod.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find path for module: {}.", module_name);
        return {};
    }

    return mod->uszFullName ? std::string(mod->uszFullName) : std::string{};
}

std::vector<std::string> Process::get_modules(DWORD process_id) const {
    DWORD target_process_id = (process_id != 0) ? process_id : this->process_id;

    std::vector<std::string> modules;
    VolkResource<VMMDLL_MAP_MODULE> module_map;

    if (!VMMDLL_Map_GetModuleU(this->dma.handle.get(), target_process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to get module list.");
        return modules;
    }

    for (DWORD i = 0; i < module_map->cMap; ++i) {
        const auto& entry = module_map->pMap[i];
        if (entry.uszText) {
            modules.emplace_back(entry.uszText);
        }
    }

    return modules;
}


bool Process::fix_cr3(const std::string& process_name) {
    VolkResource<VMMDLL_MAP_MODULEENTRY> module_entry;

    if (VMMDLL_Map_GetModuleFromNameU(this->dma.handle.get(), this->process_id, process_name.c_str(), module_entry.out(), NULL)) {
        logger.debug("CR3 fix not needed.");
        return true;
    }

    if (!VMMDLL_InitializePlugins(this->dma.handle.get())) {
        logger.error("Failed to initialize plugins.");
        return false;
    }

    Sleep(500);

    while (true) {
        BYTE bytes[4] = { 0 };
        DWORD i = 0;
        auto nt = VMMDLL_VfsReadW(this->dma.handle.get(), (LPWSTR)L"\\misc\\procinfo\\progress_percent.txt", bytes, 3, &i, 0);
        if (nt == VMMDLL_STATUS_SUCCESS && atoi((LPSTR)bytes) == 100)
            break;
        Sleep(100);
    }

    VMMDLL_VFS_FILELIST2 VfsFileList;
    VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
    VfsFileList.h = 0;
    VfsFileList.pfnAddDirectory = nullptr;
    VfsFileList.pfnAddFile = cb_add_file;

    if (!VMMDLL_VfsListU(this->dma.handle.get(), (LPSTR)"\\misc\\procinfo\\", &VfsFileList))
        return false;

    const size_t buffer_size = cb_size;
    std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
    DWORD j = 0;
    auto nt = VMMDLL_VfsReadW(this->dma.handle.get(), (LPWSTR)L"\\misc\\procinfo\\dtb.txt", bytes.get(), buffer_size - 1, &j, 0);
    if (nt != VMMDLL_STATUS_SUCCESS)
        return false;

    std::vector<uint64_t> possible_dtbs;
    std::string lines(reinterpret_cast<char*>(bytes.get()));
    std::istringstream iss(lines);
    std::string line;

    while (std::getline(iss, line)) {
        uint32_t index;
        DWORD process_id;
        uint64_t dtb;
        uint64_t kernel_address;
        std::string name;

        std::istringstream info_ss(line);
        if (info_ss >> std::hex >> index >> std::dec >> process_id >> std::hex >> dtb >> kernel_address >> name) {
            if (process_id == 0 || process_name.find(name) != std::string::npos) {
                possible_dtbs.push_back(dtb);
            }
        }
    }

    for (const auto& dtb : possible_dtbs) {
        VMMDLL_ConfigSet(this->dma.handle.get(), VMMDLL_OPT_PROCESS_DTB | this->process_id, dtb);
        if (VMMDLL_Map_GetModuleFromNameU(this->dma.handle.get(), this->process_id, process_name.c_str(), module_entry.out(), NULL)) {
            static ULONG64 pml4_first[512];
            static ULONG64 pml4_second[512];
            DWORD read_size;

            if (!VMMDLL_MemReadEx(this->dma.handle.get(), -1, dtb, reinterpret_cast<PBYTE>(pml4_first), sizeof(pml4_first), &read_size,
                VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
                logger.error("Failed to read PML4 the first time.");
                return false;
            }

            if (!VMMDLL_MemReadEx(this->dma.handle.get(), -1, dtb, reinterpret_cast<PBYTE>(pml4_second), sizeof(pml4_second), &read_size,
                VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
                logger.error("Failed to read PML4 the second time.");
                return false;
            }

            if (memcmp(pml4_first, pml4_second, sizeof(pml4_first)) != 0) {
                logger.error("PML4 mismatch between reads.");
                return false;
            }

            VMMDLL_MemReadEx((VMM_HANDLE)-666, 333, (ULONG64)pml4_first, nullptr, 0, nullptr, 0);
            VMMDLL_ConfigSet(this->dma.handle.get(), VMMDLL_OPT_PROCESS_DTB | this->process_id, 666);

            return true;
        }
    }

    logger.error("Failed to patch process: {}.", process_name);
    return false;
}

bool Process::virtual_to_physical(uint64_t virtual_address, uint64_t& physical_address) const {
    if (!this->is_valid_address(virtual_address)) {
        return false;
    }

    return VMMDLL_VirtualToPhysical(this->dma.handle.get(), virtual_address, &physical_address);
}

bool Process::read(uint64_t address, void* buffer, size_t size) const {
    if (!this->is_valid_address(address)) {
        return false;
    }

    DWORD read_size = 0;
    if (!VMMDLL_MemReadEx(this->dma.handle.get(), this->process_id, address, static_cast<PBYTE>(buffer), size, &read_size, VMMDLL_FLAG_NOCACHE)) {
        logger.error("Failed to read memory at 0x{:x} (PID: {}).", address, this->process_id);
        return false;
    }

    return read_size == size;
}

uint64_t Process::read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
    uint64_t result = this->read<uint64_t>(base + offsets.at(0));
    for (size_t i = 1; i < offsets.size(); ++i) {
        result = this->read<uint64_t>(result + offsets.at(i));
    }
    return result;
}

bool Process::write(uint64_t address, void* buffer, size_t size, DWORD process_id) const {
    if (!this->is_valid_address(address)) {
        return false;
    }

    DWORD target_process_id = (process_id == 0) ? this->process_id : process_id;

    if (!VMMDLL_MemWrite(this->dma.handle.get(), target_process_id, address, static_cast<PBYTE>(buffer), size)) {
        logger.error("Failed to write memory at 0x{:x} (PID: {}).", address, target_process_id);
        return false;
    }

    return true;
}

VMMDLL_SCATTER_HANDLE Process::create_scatter(DWORD process_id) const {
    DWORD target_process_id = (process_id != 0) ? process_id : this->process_id;
    VMMDLL_SCATTER_HANDLE scatter_handle = VMMDLL_Scatter_Initialize(this->dma.handle.get(), target_process_id, scatter_flags);
    if (!scatter_handle) {
        logger.error("Failed to create scatter handle.");
    }
    return scatter_handle;
}

void Process::close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const {
    if (scatter_handle) {
        VMMDLL_Scatter_CloseHandle(scatter_handle);
        this->scatter_counts.erase(scatter_handle);
    }
}

bool Process::add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const {
    if (!this->is_valid_address(address)) {
        return false;
    }

    if (!VMMDLL_Scatter_PrepareEx(scatter_handle, address, size, static_cast<PBYTE>(buffer), NULL)) {
        logger.error("Failed to prepare scatter read at 0x{:x}.", address);
        return false;
    }
    ++this->scatter_counts[scatter_handle];

    return true;
}

bool Process::add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const {
    if (!this->is_valid_address(address)) {
        return false;
    }

    if (!VMMDLL_Scatter_PrepareWrite(scatter_handle, address, static_cast<PBYTE>(buffer), size)) {
        logger.error("Failed to prepare scatter write at 0x{:x}.", address);
        return false;
    }
    ++this->scatter_counts[scatter_handle];

    return true;
}

bool Process::execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, DWORD process_id) const {
    auto it = this->scatter_counts.find(scatter_handle);
    if (it == this->scatter_counts.end() || it->second == 0) {
        return true;
    }

    DWORD target_process_id = (process_id != 0) ? process_id : this->process_id;
    bool success = true;

    if (!VMMDLL_Scatter_Execute(scatter_handle)) {
        logger.error("Failed to execute scatter.");
        success = false;
    }

    if (!VMMDLL_Scatter_Clear(scatter_handle, target_process_id, scatter_flags)) {
        logger.error("Failed to clear scatter.");
        success = false;
    }

    it->second = 0;

    return success;
}