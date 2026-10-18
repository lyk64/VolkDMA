#include "src/local/local.hh"

#include <VolkLog/log.hh>

#include <cstring>
#include <optional>
#include <utility>
#include <vector>
#include <tlhelp32.h>

namespace volk::dma::local {

namespace {

constexpr volk::log::Logger logger{ "dma.process" };

constexpr DWORD access_rights = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION;

template <class Visitor>
bool for_each_module(uint32_t process_id, Visitor&& visit) {
    const UniqueHandle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id) };
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W entry{ .dwSize = sizeof(MODULEENTRY32W) };
    for (BOOL more = Module32FirstW(snapshot.get(), &entry); more; more = Module32NextW(snapshot.get(), &entry)) {
        if (!visit(entry)) {
            break;
        }
    }

    return true;
}

class LocalProcess final : public detail::ProcessBackend {
public:
    explicit LocalProcess(uint32_t process_id)
        : process_id(process_id), handle(OpenProcess(access_rights, FALSE, process_id), HandleCloser{}) {
        if (!handle) {
            logger.error("Failed to open PID {} (error {}).", process_id, GetLastError());
        }
    }

    std::optional<size_t> read(uint64_t address, void* buffer, size_t size) const override {
        if (!handle) {
            return std::nullopt;
        }

        SIZE_T read_size = 0;
        if (!ReadProcessMemory(handle.get(), reinterpret_cast<LPCVOID>(address), buffer, size, &read_size)) {
            std::memset(static_cast<std::byte*>(buffer) + read_size, 0, size - read_size);
        }

        return read_size;
    }

    bool write(uint32_t target_process_id, uint64_t address, const void* buffer, size_t size) const override {
        if (!handle || target_process_id != process_id) {
            return false;
        }

        SIZE_T written = 0;
        return WriteProcessMemory(handle.get(), reinterpret_cast<LPVOID>(address), buffer, size, &written) && written == size;
    }

    std::optional<detail::ModuleInfo> module(const std::string& module_name) const override {
        const std::wstring wanted = widen(module_name);
        std::optional<detail::ModuleInfo> found;

        for_each_module(process_id, [&](const MODULEENTRY32W& entry) {
            if (_wcsicmp(entry.szModule, wanted.c_str()) != 0) {
                return true;
            }

            found = detail::ModuleInfo{
                .base = reinterpret_cast<uint64_t>(entry.modBaseAddr),
                .size = entry.modBaseSize,
                .path = narrow(entry.szExePath),
            };
            return false;
        });

        return found;
    }

    uint64_t export_address(const std::string& module_name, const std::string& export_name) const override {
        const std::optional<detail::ModuleInfo> image = module(module_name);
        if (!image) {
            return 0;
        }

        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        if (!read_exact(image->base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
            !read_exact(image->base + dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        const IMAGE_DATA_DIRECTORY& directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY exports{};
        if (directory.VirtualAddress == 0 || !read_exact(image->base + directory.VirtualAddress, &exports, sizeof(exports))) {
            return 0;
        }

        std::vector<DWORD> names(exports.NumberOfNames);
        std::vector<WORD> ordinals(exports.NumberOfNames);
        std::vector<DWORD> functions(exports.NumberOfFunctions);
        if (!read_exact(image->base + exports.AddressOfNames, names.data(), names.size() * sizeof(DWORD)) ||
            !read_exact(image->base + exports.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD)) ||
            !read_exact(image->base + exports.AddressOfFunctions, functions.data(), functions.size() * sizeof(DWORD))) {
            return 0;
        }

        std::string name(export_name.size() + 1, '\0');
        for (size_t i = 0; i < names.size(); ++i) {
            if (!read_exact(image->base + names[i], name.data(), name.size()) || name.compare(0, export_name.size(), export_name) != 0 || name.back() != '\0') {
                continue;
            }

            if (ordinals[i] >= functions.size()) {
                return 0;
            }

            return image->base + functions[ordinals[i]];
        }

        return 0;
    }

    std::optional<std::vector<std::string>> modules(uint32_t target_process_id) const override {
        std::vector<std::string> names;
        const bool listed = for_each_module(target_process_id, [&](const MODULEENTRY32W& entry) {
            names.push_back(narrow(entry.szModule));
            return true;
        });

        if (!listed) {
            return std::nullopt;
        }

        return names;
    }

    bool fix_cr3(const std::string&, std::stop_token) override {
        return static_cast<bool>(handle);
    }

    std::unique_ptr<detail::ScatterBackend> create_scatter(uint32_t target_process_id) const override {
        if (target_process_id != process_id) {
            logger.error("Local scatters can only target their own process (PID {}, requested {}).", process_id, target_process_id);
            return open_scatter(nullptr, target_process_id);
        }

        return open_scatter(handle, target_process_id);
    }

private:
    uint32_t process_id;
    ProcessHandle handle;

    [[nodiscard]] bool read_exact(uint64_t address, void* buffer, size_t size) const {
        return read(address, buffer, size) == size;
    }
};

} // namespace

std::shared_ptr<detail::ProcessBackend> open_process(uint32_t process_id) {
    return std::make_shared<LocalProcess>(process_id);
}

} // namespace volk::dma::local
