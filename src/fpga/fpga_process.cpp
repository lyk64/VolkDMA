#include "src/fpga/fpga.hh"

#include <VolkLog/log.hh>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <format>
#include <limits>
#include <ranges>
#include <span>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>
#include <windows.h>

#include "external/vmm/vmmdll.h"

#include "src/fpga/resource.hh"

namespace volk::dma::fpga {

namespace {

constexpr volk::log::Logger logger{ "dma.process" };

enum class VadAccess : uint32_t {
    none,
    read,
    execute,
    execute_read,
    read_write,
    write_copy,
    execute_read_write,
    execute_write_copy,
};

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

bool wait_for_procinfo_scan(VMM_HANDLE handle, std::stop_token stop_token) {
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

        if (stop_token.stop_requested()) {
            logger.info("Cancelled the procinfo PFN scan (last progress {}%).", last_percent);
            return false;
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

class FpgaProcess final : public detail::ProcessBackend {
public:
    FpgaProcess(VmmHandle vmm, uint32_t process_id) : vmm(std::move(vmm)), process_id(process_id) {}

    std::optional<size_t> read(uint64_t address, void* buffer, size_t size) const override {
        DWORD read_size = 0;
        if (!VMMDLL_MemReadEx(vmm.get(), process_id, address, static_cast<PBYTE>(buffer), static_cast<DWORD>(size), &read_size, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
            return std::nullopt;
        }

        return read_size;
    }

    bool write(uint32_t target_process_id, uint64_t address, const void* buffer, size_t size) const override {
        return VMMDLL_MemWrite(vmm.get(), target_process_id, address, static_cast<PBYTE>(const_cast<void*>(buffer)), static_cast<DWORD>(size));
    }

    std::optional<detail::ModuleInfo> module(const std::string& module_name) const override {
        detail::Resource<VMMDLL_MAP_MODULEENTRY> module_entry{};
        if (!VMMDLL_Map_GetModuleFromNameU(vmm.get(), process_id, module_name.c_str(), module_entry.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
            return std::nullopt;
        }

        return detail::ModuleInfo{
            .base = static_cast<uint64_t>(module_entry->vaBase),
            .size = static_cast<size_t>(module_entry->cbImageSize),
            .path = module_entry->uszFullName ? std::string(module_entry->uszFullName) : std::string{},
        };
    }

    uint64_t export_address(const std::string& module_name, const std::string& export_name) const override {
        return VMMDLL_ProcessGetProcAddressU(vmm.get(), process_id, module_name.c_str(), export_name.c_str());
    }

    std::optional<std::vector<std::string>> modules(uint32_t target_process_id) const override {
        detail::Resource<VMMDLL_MAP_MODULE> module_map;
        if (!VMMDLL_Map_GetModuleU(vmm.get(), target_process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
            return std::nullopt;
        }

        std::vector<std::string> names;
        for (DWORD i = 0; i < module_map->cMap; ++i) {
            const auto& entry = module_map->pMap[i];
            if (entry.uszText) {
                names.emplace_back(entry.uszText);
            }
        }

        return names;
    }

    std::optional<std::vector<MemoryRegion>> regions() const override {
        detail::Resource<VMMDLL_MAP_VAD> vad_map;
        if (!VMMDLL_Map_GetVadU(vmm.get(), process_id, FALSE, vad_map.out()) || vad_map->dwVersion != VMMDLL_MAP_VAD_VERSION) {
            return std::nullopt;
        }

        std::vector<MemoryRegion> regions;
        regions.reserve(vad_map->cMap);
        for (const VMMDLL_MAP_VADENTRY& entry : std::span<const VMMDLL_MAP_VADENTRY>{ vad_map->pMap, vad_map->cMap }) {
            const auto access = static_cast<VadAccess>(entry.Protection & 7);
            const bool guard = (entry.Protection >> 3) == 2;
            regions.push_back({
                .base = entry.vaStart,
                .size = entry.vaEnd - entry.vaStart + 1,
                .readable = !guard && access != VadAccess::none && access != VadAccess::execute,
                .writable = !guard && access >= VadAccess::read_write,
                .executable = !guard && (access == VadAccess::execute || access == VadAccess::execute_read ||
                                         access == VadAccess::execute_read_write || access == VadAccess::execute_write_copy),
                .is_private = entry.fPrivateMemory != 0,
            });
        }

        return regions;
    }

    bool fix_cr3(const std::string& module_name, std::stop_token stop_token) override {
        if (process_id == 0) {
            logger.error("Cannot fix CR3: the process was not found.");
            return false;
        }

        const std::string_view wanted_module = module_name.empty() ? std::string_view{ "a loader-list module" } : std::string_view{ module_name };
        const auto check_translation = [this, &module_name, wanted_module](std::string_view stage) {
            detail::Resource<VMMDLL_MAP_MODULE> module_map;
            if (!VMMDLL_Map_GetModuleU(vmm.get(), process_id, module_map.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                logger.debug("{}: PID {} resolves no modules.", stage, process_id);
                return false;
            }

            if (module_map->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
                logger.error("{}: module map version 0x{:x} does not match the expected 0x{:x}.", stage, module_map->dwVersion, VMMDLL_MAP_MODULE_VERSION);
                return false;
            }

            if (module_map->cMap == 0) {
                logger.debug("{}: PID {} resolves no modules.", stage, process_id);
                return false;
            }

            const std::span<const VMMDLL_MAP_MODULEENTRY> modules{ module_map->pMap, module_map->cMap };
            const auto target = std::ranges::find_if(modules, [&module_name](const VMMDLL_MAP_MODULEENTRY& entry) {
                return entry.tp == VMMDLL_MODULE_TP_NORMAL && (module_name.empty() || (entry.uszText && _stricmp(entry.uszText, module_name.c_str()) == 0));
            });
            if (target == modules.end()) {
                const VMMDLL_MAP_MODULEENTRY& first = modules.front();
                logger.debug("{}: PID {} resolves {} module(s), first '{}' at 0x{:x}, but not {}.", stage, process_id, modules.size(), first.uszText ? first.uszText : "?", first.vaBase, wanted_module);
                return false;
            }

            const std::string_view target_name = target->uszText ? target->uszText : "?";
            IMAGE_DOS_HEADER dos{};
            read(target->vaBase, &dos, sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
                logger.debug("{}: PID {} resolves {} module(s) but {} at 0x{:x} did not read back as 'MZ'.", stage, process_id, modules.size(), target_name, target->vaBase);
                return false;
            }

            logger.info("{}: PID {} resolves {} module(s); verified 'MZ' for {} at 0x{:x}.", stage, process_id, modules.size(), target_name, target->vaBase);
            return true;
        };

        if (check_translation("Current DTB")) {
            return true;
        }

        logger.info("CR3 fix needed: PID {} failed verification; searching for candidate DTBs.", process_id);

        if (!wait_for_procinfo_scan(vmm.get(), stop_token)) {
            return false;
        }

        const std::optional<std::string> dtb_txt = read_vfs_file(vmm.get(), "\\misc\\procinfo\\", "dtb.txt");
        if (!dtb_txt) {
            return false;
        }

        const std::vector<uint64_t> candidates = parse_candidate_dtbs(*dtb_txt, process_id);
        for (const auto [index, dtb] : std::views::enumerate(candidates)) {
            if (stop_token.stop_requested()) {
                VMMDLL_ConfigSet(vmm.get(), VMMDLL_OPT_PROCESS_DTB | process_id, 0);
                logger.info("Cancelled the CR3 fix at candidate {} of {}.", index + 1, candidates.size());
                return false;
            }

            VMMDLL_ConfigSet(vmm.get(), VMMDLL_OPT_PROCESS_DTB | process_id, dtb);
            if (check_translation(std::format("Candidate {} of {} (DTB 0x{:x})", index + 1, candidates.size(), dtb))) {
                logger.info("CR3 fixed: using DTB 0x{:x} (candidate {} of {}).", dtb, index + 1, candidates.size());
                return true;
            }
        }

        VMMDLL_ConfigSet(vmm.get(), VMMDLL_OPT_PROCESS_DTB | process_id, 0);
        logger.error("Failed to patch PID {}: none of the {} candidate DTB(s) verified {}.", process_id, candidates.size(), wanted_module);
        return false;
    }

    std::unique_ptr<detail::ScatterBackend> create_scatter(uint32_t target_process_id) const override {
        return open_scatter(vmm, target_process_id);
    }

private:
    VmmHandle vmm;
    uint32_t process_id;
};

} // namespace

std::shared_ptr<detail::ProcessBackend> open_process(VmmHandle vmm, uint32_t process_id) {
    return std::make_shared<FpgaProcess>(std::move(vmm), process_id);
}

} // namespace volk::dma::fpga
