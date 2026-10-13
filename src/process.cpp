#include "include/VolkDMA/process.hh"

#include <VolkLog/log.hh>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <windows.h>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/dma.hh"
#include "detail/resource.hh"
#include "include/VolkDMA/scatter.hh"

namespace volk::dma {

static constexpr volk::log::Logger logger{ "PROCESS" };

std::expected<Process, AttachError> Process::attach(const Device& dma, const std::string& process_name, const std::string& module_name) {
    const std::optional<uint32_t> process_id = dma.get_process_id(process_name);
    if (!process_id) {
        return std::unexpected(AttachError::not_running);
    }

    Process process(dma, *process_id);
    if (!process.fix_cr3(module_name)) {
        return std::unexpected(AttachError::translation_failed);
    }

    return process;
}

Process::Process(const Device& dma, uint32_t process_id) : vmm(dma.get_handle()), process_id(process_id) {}

uint64_t Process::get_base_address(const std::string& module_name) const {
    detail::Resource<VMMDLL_MAP_MODULEENTRY> module_entry{};

    if (!VMMDLL_Map_GetModuleFromNameU(this->vmm, this->process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find base address of module: {}.", module_name);
        return 0;
    }

    return static_cast<uint64_t>(module_entry->vaBase);
}

uint64_t Process::get_export(const std::string& module_name, const std::string& export_name) const {
    const uint64_t address = VMMDLL_ProcessGetProcAddressU(this->vmm, this->process_id, module_name.c_str(), export_name.c_str());
    if (!address) {
        logger.error("Failed to resolve export {} in module {} (PID: {}).", export_name, module_name, this->process_id);
    }

    return address;
}

size_t Process::get_size(const std::string& module_name) const {
    detail::Resource<VMMDLL_MAP_MODULEENTRY> module_entry{};

    if (!VMMDLL_Map_GetModuleFromNameU(this->vmm, this->process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
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
    detail::Resource<VMMDLL_MAP_MODULEENTRY> mod;

    if (!VMMDLL_Map_GetModuleFromNameU(this->vmm, this->process_id, module_name.c_str(), mod.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
        logger.error("Failed to find path for module: {}.", module_name);
        return {};
    }

    return mod->uszFullName ? std::string(mod->uszFullName) : std::string{};
}

std::vector<std::string> Process::get_modules(uint32_t process_id) const {
    DWORD target_process_id = (process_id != 0) ? process_id : this->process_id;

    std::vector<std::string> modules;
    detail::Resource<VMMDLL_MAP_MODULE> module_map;

    if (!VMMDLL_Map_GetModuleU(this->vmm, target_process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
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

namespace {

std::optional<int> read_procinfo_progress(VMM_HANDLE handle) {
    std::array<char, 3> raw{};
    DWORD cb_read = 0;
    if (VMMDLL_VfsReadU(handle, "\\misc\\procinfo\\progress_percent.txt", reinterpret_cast<PBYTE>(raw.data()), static_cast<DWORD>(raw.size()), &cb_read, 0) != VMMDLL_STATUS_SUCCESS) {
        return std::nullopt;
    }

    int percent = 0;
    if (std::from_chars(raw.data(), raw.data() + cb_read, percent).ec != std::errc{}) {
        return std::nullopt;
    }

    return percent;
}

bool wait_for_procinfo_scan(VMM_HANDLE handle) {
    using namespace std::chrono_literals;

    if (!VMMDLL_InitializePlugins(handle)) {
        logger.error("Failed to initialize plugins.");
        return false;
    }

    constexpr auto scan_timeout = 60s;
    const auto scan_start = std::chrono::steady_clock::now();
    const auto deadline = scan_start + scan_timeout;

    int last_percent = -1;
    while (std::chrono::steady_clock::now() < deadline) {
        last_percent = read_procinfo_progress(handle).value_or(last_percent);
        if (last_percent == 100) {
            logger.debug("PFN scan completed in {}.", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - scan_start));
            return true;
        }

        std::this_thread::sleep_for(100ms);
    }

    logger.error("Timed out after {} waiting for the procinfo PFN scan (last progress {}%).", scan_timeout, last_percent);
    return false;
}

std::optional<std::string> read_vfs_file(VMM_HANDLE handle, const std::string& directory, std::string_view file_name) {
    const detail::Resource<VMMDLL_VFS_FILELISTBLOB> listing{ VMMDLL_VfsListBlobU(handle, directory.c_str()) };
    if (!listing || listing->dwVersion != VMMDLL_VFS_FILELISTBLOB_VERSION) {
        logger.error("Failed to list {}.", directory);
        return std::nullopt;
    }

    const std::span<const VMMDLL_VFS_FILELISTBLOB_ENTRY> entries{ listing->FileEntry, listing->cFileEntry };
    const auto entry = std::ranges::find(entries, file_name, [&listing](const VMMDLL_VFS_FILELISTBLOB_ENTRY& candidate) {
        return std::string_view(listing->uszMultiText + candidate.ouszName);
    });
    if (entry == entries.end() || entry->cbFileSize == 0 || entry->cbFileSize > (std::numeric_limits<DWORD>::max)()) {
        logger.error("{}{} was not listed, is empty, or is not a readable file.", directory, file_name);
        return std::nullopt;
    }

    const std::string path = std::format("{}{}", directory, file_name);
    std::string content(static_cast<size_t>(entry->cbFileSize), '\0');
    DWORD cb_read = 0;
    if (const NTSTATUS status = VMMDLL_VfsReadU(handle, path.c_str(), reinterpret_cast<PBYTE>(content.data()), static_cast<DWORD>(content.size()), &cb_read, 0);
        status != VMMDLL_STATUS_SUCCESS) {
        logger.error("Failed to read {} (status 0x{:x}).", path, static_cast<uint32_t>(status));
        return std::nullopt;
    }

    logger.debug("Read 0x{:x} of 0x{:x} bytes from {}.", cb_read, content.size(), path);
    content.resize(cb_read);
    return content;
}

std::vector<uint64_t> parse_candidate_dtbs(const std::string& dtb_txt, uint32_t process_id) {
    std::vector<uint64_t> candidates;
    size_t parsed_entries = 0;
    size_t unowned = 0;
    size_t owned = 0;

    std::istringstream lines{ dtb_txt };
    for (std::string line; std::getline(lines, line);) {
        uint32_t index = 0;
        uint32_t entry_process_id = 0;
        uint64_t dtb = 0;
        uint64_t kernel_address = 0;
        std::string name;

        std::istringstream fields{ line };
        if (!(fields >> std::hex >> index >> std::dec >> entry_process_id >> std::hex >> dtb >> kernel_address >> name)) {
            continue;
        }

        ++parsed_entries;
        if (entry_process_id == 0) {
            ++unowned;
        } else if (entry_process_id == process_id) {
            ++owned;
        } else {
            continue;
        }
        candidates.push_back(dtb);
    }

    logger.info("Parsed {} dtb.txt entries; {} candidate DTB(s) ({} unowned, {} own PID).", parsed_entries, candidates.size(), unowned, owned);
    return candidates;
}

} // namespace

bool Process::fix_cr3(const std::string& module_name) {
    if (this->process_id == 0) {
        logger.error("Cannot fix CR3: the process was not found.");
        return false;
    }

    const std::string_view wanted_module = module_name.empty() ? std::string_view{ "a loader-list module" } : std::string_view{ module_name };
    const auto check_translation = [this, &module_name, wanted_module](std::string_view stage) {
        detail::Resource<VMMDLL_MAP_MODULE> module_map;
        if (!VMMDLL_Map_GetModuleU(this->vmm, this->process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
            logger.debug("{}: PID {} resolves no modules.", stage, this->process_id);
            return false;
        }

        if (module_map->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
            logger.error("{}: module map version 0x{:x} does not match the expected 0x{:x}.", stage, module_map->dwVersion, VMMDLL_MAP_MODULE_VERSION);
            return false;
        }

        if (module_map->cMap == 0) {
            logger.debug("{}: PID {} resolves no modules.", stage, this->process_id);
            return false;
        }

        const std::span<const VMMDLL_MAP_MODULEENTRY> modules{ module_map->pMap, module_map->cMap };
        const auto target = std::ranges::find_if(modules, [&module_name](const VMMDLL_MAP_MODULEENTRY& entry) {
            return entry.tp == VMMDLL_MODULE_TP_NORMAL && (module_name.empty() || (entry.uszText && _stricmp(entry.uszText, module_name.c_str()) == 0));
        });
        if (target == modules.end()) {
            const VMMDLL_MAP_MODULEENTRY& first = modules.front();
            logger.debug("{}: PID {} resolves {} module(s), first '{}' at 0x{:x}, but not {}.", stage, this->process_id, modules.size(), first.uszText ? first.uszText : "?", first.vaBase, wanted_module);
            return false;
        }

        const std::string_view target_name = target->uszText ? target->uszText : "?";
        if (this->read<IMAGE_DOS_HEADER>(target->vaBase).e_magic != IMAGE_DOS_SIGNATURE) {
            logger.debug("{}: PID {} resolves {} module(s) but {} at 0x{:x} did not read back as 'MZ'.", stage, this->process_id, modules.size(), target_name, target->vaBase);
            return false;
        }

        logger.info("{}: PID {} resolves {} module(s); verified 'MZ' for {} at 0x{:x}.", stage, this->process_id, modules.size(), target_name, target->vaBase);
        return true;
    };

    if (check_translation("Current DTB")) {
        return true;
    }

    logger.info("CR3 fix needed: PID {} failed verification; searching for candidate DTBs.", this->process_id);

    if (!wait_for_procinfo_scan(this->vmm)) {
        return false;
    }

    const std::optional<std::string> dtb_txt = read_vfs_file(this->vmm, "\\misc\\procinfo\\", "dtb.txt");
    if (!dtb_txt) {
        return false;
    }

    const std::vector<uint64_t> candidates = parse_candidate_dtbs(*dtb_txt, this->process_id);
    for (const auto [index, dtb] : std::views::enumerate(candidates)) {
        VMMDLL_ConfigSet(this->vmm, VMMDLL_OPT_PROCESS_DTB | this->process_id, dtb);
        if (check_translation(std::format("Candidate {} of {} (DTB 0x{:x})", index + 1, candidates.size(), dtb))) {
            logger.info("CR3 fixed: using DTB 0x{:x} (candidate {} of {}).", dtb, index + 1, candidates.size());
            return true;
        }
    }

    VMMDLL_ConfigSet(this->vmm, VMMDLL_OPT_PROCESS_DTB | this->process_id, 0);
    logger.error("Failed to patch PID {}: none of the {} candidate DTB(s) verified {}.", this->process_id, candidates.size(), wanted_module);
    return false;
}

bool Process::read(uint64_t address, void* buffer, size_t size) const {
    if (!is_valid_address(address)) {
        std::memset(buffer, 0, size);
        return false;
    }

    DWORD read_size = 0;
    if (!VMMDLL_MemReadEx(this->vmm, this->process_id, address, static_cast<PBYTE>(buffer), static_cast<DWORD>(size), &read_size, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
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

    if (!VMMDLL_MemReadEx(this->vmm, this->process_id, range_start, buffer.data(), static_cast<DWORD>(size), nullptr, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
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

    if (!VMMDLL_MemWrite(this->vmm, target_process_id, address, static_cast<PBYTE>(const_cast<void*>(buffer)), static_cast<DWORD>(size))) {
        logger.error("Failed to write memory at 0x{:x} (PID: {}).", address, target_process_id);
        return false;
    }

    return true;
}

Scatter Process::create_scatter(uint32_t process_id) const {
    return Scatter(this->vmm, (process_id != 0) ? process_id : this->process_id);
}

} // namespace volk::dma
