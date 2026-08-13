#include "include/VolkDMA/process.hh"

#include <VolkLog/log.hh>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <windows.h>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/dma.hh"
#include "include/VolkDMA/internal/volkresource.hh"
#include "include/VolkDMA/scatter.hh"

static constexpr Volk::Log::Logger logger{ "PROCESS" };

Process::Process(const DMA& dma, const std::string& process_name) : dma(dma), process_id(dma.get_process_id(process_name)) {}
Process::Process(const DMA& dma, uint32_t process_id) : dma(dma), process_id(process_id) {}

uint64_t Process::get_base_address(const std::string& module_name) const {
    VolkResource<VMMDLL_MAP_MODULEENTRY> module_entry{};

    if (!VMMDLL_Map_GetModuleFromNameU(this->dma.get_handle(), this->process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find base address of module: {}.", module_name);
        return 0;
    }

    return static_cast<uint64_t>(module_entry->vaBase);
}

uint64_t Process::get_export(const std::string& module_name, const std::string& export_name) const {
    const uint64_t address = VMMDLL_ProcessGetProcAddressU(this->dma.get_handle(), this->process_id, module_name.c_str(), export_name.c_str());
    if (!address) {
        logger.error("Failed to resolve export {} in module {} (PID: {}).", export_name, module_name, this->process_id);
    }

    return address;
}

size_t Process::get_size(const std::string& module_name) const {
    VolkResource<VMMDLL_MAP_MODULEENTRY> module_entry{};

    if (!VMMDLL_Map_GetModuleFromNameU(this->dma.get_handle(), this->process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
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

    if (!this->read(base_address, image_buffer.get(), image_size)) {
        logger.warn("Partial read for module dump: {}.", module_name);
    }
    auto section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(image_buffer.get() + dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader);

    for (size_t i = 0; i < nt.FileHeader.NumberOfSections; i++, section_header++) {
        section_header->PointerToRawData = section_header->VirtualAddress;
        section_header->SizeOfRawData = section_header->Misc.VirtualSize;
    }

    HANDLE file_handle = CreateFileW(std::filesystem::path(path).wstring().c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_COMPRESSED, NULL);
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

    if (!VMMDLL_Map_GetModuleFromNameU(this->dma.get_handle(), this->process_id, module_name.c_str(), mod.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find path for module: {}.", module_name);
        return {};
    }

    return mod->uszFullName ? std::string(mod->uszFullName) : std::string{};
}

std::vector<std::string> Process::get_modules(uint32_t process_id) const {
    DWORD target_process_id = (process_id != 0) ? process_id : this->process_id;

    std::vector<std::string> modules;
    VolkResource<VMMDLL_MAP_MODULE> module_map;

    if (!VMMDLL_Map_GetModuleU(this->dma.get_handle(), target_process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
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


bool Process::fix_cr3() {
    const auto check_translation = [this](std::string_view stage) {
        VolkResource<VMMDLL_MAP_MODULE> module_map;
        if (!VMMDLL_Map_GetModuleU(this->dma.get_handle(), this->process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL) || module_map->cMap == 0) {
            return false;
        }

        const uint64_t base = module_map->pMap[0].vaBase;
        IMAGE_DOS_HEADER dos{};
        if (this->read(base, &dos, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
            logger.info("{}: PID {} resolves {} module(s); verified 'MZ' at 0x{:x}.", stage, this->process_id, module_map->cMap, base);
        } else {
            logger.error("{}: PID {} resolves {} module(s) but 0x{:x} did not read back as 'MZ'.", stage, this->process_id, module_map->cMap, base);
        }
        return true;
    };

    if (check_translation("CR3 fix not needed")) {
        return true;
    }

    logger.info("CR3 fix needed: PID {} resolves no modules; searching for candidate DTBs.", this->process_id);

    if (!VMMDLL_InitializePlugins(this->dma.get_handle())) {
        logger.error("Failed to initialize plugins.");
        return false;
    }

    constexpr std::chrono::seconds scan_timeout{ 60 };
    const auto scan_start = std::chrono::steady_clock::now();

    int last_percent = -1;
    for (;;) {
        BYTE raw[4] = {};
        DWORD cb_progress = 0;
        if (VMMDLL_VfsReadU(this->dma.get_handle(), "\\misc\\procinfo\\progress_percent.txt", raw, 3, &cb_progress, 0) == VMMDLL_STATUS_SUCCESS) {
            const auto* first = reinterpret_cast<const char*>(raw);
            int percent = 0;
            if (std::from_chars(first, first + cb_progress, percent).ec == std::errc{}) {
                last_percent = percent;
                if (percent == 100) {
                    break;
                }
            }
        }

        if (std::chrono::steady_clock::now() - scan_start >= scan_timeout) {
            logger.error("Timed out after {}s waiting for the procinfo PFN scan (last progress {}%).", scan_timeout.count(), last_percent);
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    logger.debug("PFN scan completed in {}ms.", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - scan_start).count());

    const VolkResource<VMMDLL_VFS_FILELISTBLOB> listing{ VMMDLL_VfsListBlobU(this->dma.get_handle(), "\\misc\\procinfo\\") };
    if (!listing) {
        logger.error("Failed to list \\misc\\procinfo\\.");
        return false;
    }

    uint64_t dtb_txt_size = 0;
    for (DWORD i = 0; i < listing->cFileEntry; ++i) {
        const auto& entry = listing->FileEntry[i];
        if (strcmp(listing->uszMultiText + entry.ouszName, "dtb.txt") == 0) {
            dtb_txt_size = entry.cbFileSize;
            break;
        }
    }

    if (dtb_txt_size == 0) {
        logger.error("\\misc\\procinfo\\dtb.txt was not listed, or is empty.");
        return false;
    }

    const auto buffer_size = static_cast<size_t>(dtb_txt_size);
    const auto buffer = std::make_unique<BYTE[]>(buffer_size);

    DWORD cb_read = 0;
    if (const NTSTATUS status = VMMDLL_VfsReadU(this->dma.get_handle(), "\\misc\\procinfo\\dtb.txt", buffer.get(), static_cast<DWORD>(buffer_size), &cb_read, 0);
        status != VMMDLL_STATUS_SUCCESS) {
        logger.error("Failed to read dtb.txt (status 0x{:x}).", static_cast<uint32_t>(status));
        return false;
    }

    logger.debug("Read 0x{:x} of 0x{:x} bytes from dtb.txt.", cb_read, buffer_size);

    std::vector<uint64_t> possible_dtbs;
    std::istringstream lines{ std::string(reinterpret_cast<const char*>(buffer.get()), cb_read) };
    std::string line;
    size_t parsed_entries = 0;
    size_t matched_unowned = 0;
    size_t matched_ours = 0;

    while (std::getline(lines, line)) {
        uint32_t index = 0;
        DWORD entry_process_id = 0;
        uint64_t dtb = 0;
        uint64_t kernel_address = 0;
        std::string name;

        std::istringstream fields(line);
        if (fields >> std::hex >> index >> std::dec >> entry_process_id >> std::hex >> dtb >> kernel_address >> name) {
            ++parsed_entries;
            const bool unowned = (entry_process_id == 0);
            const bool ours = (entry_process_id == this->process_id);
            if (unowned || ours) {
                unowned ? ++matched_unowned : ++matched_ours;
                possible_dtbs.push_back(dtb);
                logger.debug("Candidate DTB 0x{:x} from entry {:04x} (pid {}, name '{}') via {}.", dtb, index, entry_process_id, name, unowned ? "unowned PFN" : "own PID");
            }
        }
    }

    logger.info("Parsed {} dtb.txt entries; {} candidate DTB(s) ({} unowned, {} own PID).", parsed_entries, possible_dtbs.size(), matched_unowned, matched_ours);

    for (size_t attempt = 1; const uint64_t dtb : possible_dtbs) {
        VMMDLL_ConfigSet(this->dma.get_handle(), VMMDLL_OPT_PROCESS_DTB | this->process_id, dtb);
        if (check_translation("CR3 fixed")) {
            logger.info("Using DTB 0x{:x} (candidate {} of {}).", dtb, attempt, possible_dtbs.size());
            return true;
        }
        ++attempt;
    }

    logger.error("Failed to patch PID {}: none of the {} candidate DTB(s) resolved any modules.", this->process_id, possible_dtbs.size());
    return false;
}

bool Process::read(uint64_t address, void* buffer, size_t size) const {
    if (!is_valid_address(address)) {
        std::memset(buffer, 0, size);
        return false;
    }

    DWORD read_size = 0;
    if (!VMMDLL_MemReadEx(this->dma.get_handle(), this->process_id, address, static_cast<PBYTE>(buffer), static_cast<DWORD>(size), &read_size, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
        logger.error("Failed to read memory at 0x{:x} (PID: {}).", address, this->process_id);
        std::memset(buffer, 0, size);
        return false;
    }

    return read_size == size;
}

uint64_t Process::read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
    if (offsets.empty()) return 0;
    uint64_t result = base;
    for (size_t i = 0; i + 1 < offsets.size(); ++i) {
        result = this->read<uint64_t>(result + offsets[i]);
        if (!is_valid_address(result)) return 0;
    }
    return this->read<uint64_t>(result + offsets.back());
}

std::string Process::read_string(uint64_t address, size_t max_length) const {
    std::string buffer(max_length, '\0');
    this->read(address, buffer.data(), max_length);
    buffer.erase(std::ranges::find(buffer, '\0'), buffer.end());
    return buffer;
}

uint64_t Process::find_signature(const char* signature, uint64_t range_start, uint64_t range_end) const {
    if (!signature || !*signature || range_start >= range_end) {
        return 0;
    }

    struct PatternByte {
        uint8_t value;
        uint8_t mask;
    };

    std::vector<PatternByte> pattern;

    for (const char* pat = signature; *pat;) {
        if (*pat == ' ') {
            ++pat;
        }
        else if (*pat == '?') {
            pattern.emplace_back(0x00, 0x00);
            pat += (pat[1] == '?') ? 2 : 1;
        }
        else {
            uint8_t value = 0;
            const auto [end, ec] = std::from_chars(pat, pat + (pat[1] ? 2 : 1), value, 16);
            if (ec != std::errc{}) {
                logger.error("Malformed signature: {}.", signature);
                return 0;
            }

            pattern.emplace_back(value, 0xFF);
            pat = end;
        }
    }

    if (pattern.empty()) {
        return 0;
    }

    const uint64_t size = range_end - range_start;
    std::vector<uint8_t> buffer(size);

    if (!VMMDLL_MemReadEx(this->dma.get_handle(), this->process_id, range_start, buffer.data(), static_cast<DWORD>(size), nullptr, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
        return 0;
    }

    const auto match = std::ranges::search(buffer, pattern, [](uint8_t byte, PatternByte expected) {
        return (byte & expected.mask) == expected.value;
    });

    if (match.empty()) {
        return 0;
    }

    return range_start + static_cast<uint64_t>(match.begin() - buffer.begin());
}

bool Process::write(uint64_t address, const void* buffer, size_t size, uint32_t process_id) const {
    if (!is_valid_address(address)) {
        return false;
    }

    DWORD target_process_id = (process_id == 0) ? this->process_id : process_id;

    if (!VMMDLL_MemWrite(this->dma.get_handle(), target_process_id, address, static_cast<PBYTE>(const_cast<void*>(buffer)), static_cast<DWORD>(size))) {
        logger.error("Failed to write memory at 0x{:x} (PID: {}).", address, target_process_id);
        return false;
    }

    return true;
}

Scatter Process::create_scatter(uint32_t process_id) const {
    return Scatter(this->dma, (process_id != 0) ? process_id : this->process_id);
}