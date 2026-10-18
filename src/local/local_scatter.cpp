#include "src/local/local.hh"

#include <cstddef>
#include <cstring>
#include <utility>
#include <vector>

namespace volk::dma::local {

namespace {

class LocalScatter final : public detail::ScatterBackend {
public:
    explicit LocalScatter(ProcessHandle process) : process(std::move(process)) {}

    bool prepare_read(uint64_t address, void* buffer, size_t size) override {
        reads.push_back({ address, buffer, size });
        return true;
    }

    bool prepare_write(uint64_t address, const void* buffer, size_t size) override {
        const auto* bytes = static_cast<const std::byte*>(buffer);
        writes.push_back({ address, std::vector<std::byte>(bytes, bytes + size) });
        return true;
    }

    bool execute() override {
        for (const PendingRead& read : reads) {
            SIZE_T read_size = 0;
            if (!process || !ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(read.address), read.buffer, read.size, &read_size)) {
                std::memset(static_cast<std::byte*>(read.buffer) + read_size, 0, read.size - read_size);
            }
        }

        bool success = true;
        for (const PendingWrite& write : writes) {
            SIZE_T written = 0;
            if (!process || !WriteProcessMemory(process.get(), reinterpret_cast<LPVOID>(write.address), write.data.data(), write.data.size(), &written) || written != write.data.size()) {
                success = false;
            }
        }

        reads.clear();
        writes.clear();
        return success;
    }

private:
    struct PendingRead {
        uint64_t address;
        void* buffer;
        size_t size;
    };

    struct PendingWrite {
        uint64_t address;
        std::vector<std::byte> data;
    };

    ProcessHandle process;
    std::vector<PendingRead> reads;
    std::vector<PendingWrite> writes;
};

} // namespace

std::unique_ptr<detail::ScatterBackend> open_scatter(ProcessHandle process, uint32_t) {
    return std::make_unique<LocalScatter>(std::move(process));
}

} // namespace volk::dma::local
