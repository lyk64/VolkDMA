#include "src/local/local.hh"

#include <optional>
#include <vector>
#include <tlhelp32.h>

namespace volk::dma::local {

namespace {

std::vector<uint32_t> find_processes(const std::string& process_name, bool first_only) {
    std::vector<uint32_t> process_ids;

    const UniqueHandle snapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if (snapshot.get() == INVALID_HANDLE_VALUE) {
        return process_ids;
    }

    const std::wstring wanted = widen(process_name);
    PROCESSENTRY32W entry{ .dwSize = sizeof(PROCESSENTRY32W) };
    for (BOOL more = Process32FirstW(snapshot.get(), &entry); more; more = Process32NextW(snapshot.get(), &entry)) {
        if (_wcsicmp(entry.szExeFile, wanted.c_str()) != 0) {
            continue;
        }

        process_ids.push_back(entry.th32ProcessID);
        if (first_only) {
            break;
        }
    }

    return process_ids;
}

class LocalDevice final : public detail::DeviceBackend {
public:
    VMM_HANDLE vmm_handle() const noexcept override {
        return nullptr;
    }

    std::optional<uint32_t> process_id(const std::string& process_name) const override {
        const std::vector<uint32_t> matches = find_processes(process_name, true);
        if (matches.empty()) {
            return std::nullopt;
        }

        return matches.front();
    }

    std::vector<uint32_t> process_ids(const std::string& process_name) const override {
        return find_processes(process_name, false);
    }

    std::shared_ptr<detail::ProcessBackend> open_process(uint32_t process_id) const override {
        return local::open_process(process_id);
    }

    std::unique_ptr<detail::InputBackend> create_input(const Device&) const override {
        return open_input();
    }

    void pause_process_refresh() override {}
    void resume_process_refresh() override {}
    bool refresh_process(uint32_t) override { return true; }
};

} // namespace

std::shared_ptr<detail::DeviceBackend> open_device() {
    return std::make_shared<LocalDevice>();
}

} // namespace volk::dma::local
