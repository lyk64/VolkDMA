#include "include/VolkDMA/process.hh"

#include <VolkLog/log.hh>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <windows.h>

#include "include/VolkDMA/device.hh"
#include "include/VolkDMA/scatter.hh"
#include "detail/backend.hh"

namespace volk::dma {

static constexpr volk::log::Logger logger{ "dma.process" };

std::expected<Process, AttachError> Process::attach(const Device& dma, const std::string& process_name, const std::string& module_name, std::stop_token stop_token) {
    const std::optional<uint32_t> process_id = dma.get_process_id(process_name);
    if (!process_id) {
        return std::unexpected(AttachError::not_running);
    }

    Process process(dma, *process_id);
    if (!process.fix_cr3(module_name, stop_token)) {
        return std::unexpected(AttachError::translation_failed);
    }

    return process;
}

Process::Process(const Device& dma, uint32_t process_id) : backend(dma.backend->open_process(process_id)), process_id(process_id) {}

uint64_t Process::get_base_address(const std::string& module_name) const {
    const std::optional<detail::ModuleInfo> module = backend->module(module_name);
    if (!module) {
        logger.error("Failed to find base address of module: {}.", module_name);
        return 0;
    }

    return module->base;
}

uint64_t Process::get_export(const std::string& module_name, const std::string& export_name) const {
    const uint64_t address = backend->export_address(module_name, export_name);
    if (!address) {
        logger.error("Failed to resolve export {} in module {} (PID: {}).", export_name, module_name, this->process_id);
    }

    return address;
}

size_t Process::get_size(const std::string& module_name) const {
    const std::optional<detail::ModuleInfo> module = backend->module(module_name);
    if (!module) {
        logger.error("Failed to find size of module: {}.", module_name);
        return 0;
    }

    return module->size;
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
    const std::optional<detail::ModuleInfo> module = backend->module(module_name);
    if (!module) {
        logger.error("Failed to find path for module: {}.", module_name);
        return {};
    }

    return module->path;
}

std::vector<std::string> Process::get_modules(uint32_t process_id) const {
    const uint32_t target_process_id = (process_id != 0) ? process_id : this->process_id;

    std::optional<std::vector<std::string>> modules = backend->modules(target_process_id);
    if (!modules) {
        logger.error("Failed to get module list.");
        return {};
    }

    return std::move(*modules);
}

std::vector<MemoryRegion> Process::regions() const {
    std::optional<std::vector<MemoryRegion>> regions = backend->regions();
    if (!regions) {
        logger.error("Failed to get the memory regions of PID {}.", process_id);
        return {};
    }

    return std::move(*regions);
}

bool Process::fix_cr3(const std::string& module_name, std::stop_token stop_token) {
    return backend->fix_cr3(module_name, stop_token);
}

bool Process::read(uint64_t address, void* buffer, size_t size, profiler::Location caller) const {
    if (!is_valid_address(address)) {
        std::memset(buffer, 0, size);
        return false;
    }

    const profiler::Timed timed{ caller };

    const std::optional<size_t> read_size = backend->read(address, buffer, size);
    if (!read_size) {
        logger.error("Failed to read memory at 0x{:x} (PID: {}).", address, this->process_id);
        std::memset(buffer, 0, size);
        return false;
    }

    return *read_size == size;
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
    constexpr size_t chunk_size = 1 << 20;

    std::string text;
    while (text.size() < max_length) {
        const size_t chunk_start = text.size();
        text.resize(chunk_start + (std::min)(chunk_size, max_length - chunk_start));
        this->read(address + chunk_start, text.data() + chunk_start, text.size() - chunk_start);

        if (const size_t end = text.find('\0', chunk_start); end != std::string::npos) {
            text.resize(end);
            break;
        }
    }
    return text;
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

    if (!backend->read(range_start, buffer.data(), size)) {
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

bool Process::write(uint64_t address, const void* buffer, size_t size, uint32_t process_id, profiler::Location caller) const {
    if (!is_valid_address(address)) {
        return false;
    }

    const profiler::Timed timed{ caller };

    const uint32_t target_process_id = (process_id == 0) ? this->process_id : process_id;

    if (!backend->write(target_process_id, address, buffer, size)) {
        logger.error("Failed to write memory at 0x{:x} (PID: {}).", address, target_process_id);
        return false;
    }

    return true;
}

Scatter Process::create_scatter(uint32_t process_id) const {
    return Scatter(backend->create_scatter((process_id != 0) ? process_id : this->process_id));
}

} // namespace volk::dma
