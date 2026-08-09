#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "address.hh"

class DMA;
class Scatter;

class Process {
public:
    Process(const DMA& dma, const std::string& process_name);
    Process(const DMA& dma, uint32_t process_id);
    [[nodiscard]] uint64_t get_base_address(const std::string& module_name) const;
    [[nodiscard]] size_t get_size(const std::string& module_name) const;
    bool dump_module(const std::string& module_name, const std::string& path) const;
    [[nodiscard]] std::string get_path(const std::string& module_name) const;
    [[nodiscard]] std::vector<std::string> get_modules(uint32_t process_id = 0) const;
    bool fix_cr3();
    bool read(uint64_t address, void* buffer, size_t size) const;
    [[nodiscard]] uint64_t read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const;
    [[nodiscard]] std::string read_string(uint64_t address, size_t max_length = 256) const;
    [[nodiscard]] uint64_t find_signature(const char* signature, uint64_t range_start, uint64_t range_end) const;
    [[nodiscard]] bool write(uint64_t address, const void* buffer, size_t size, uint32_t process_id = 0) const;
    [[nodiscard]] Scatter create_scatter(uint32_t process_id = 0) const;

    template <typename T>
    [[nodiscard]] T read(uint64_t address) const {
        T buffer{};
        this->read(address, &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    [[nodiscard]] T read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const {
        if (offsets.empty()) return {};
        uint64_t result = base;
        for (size_t i = 0; i + 1 < offsets.size(); ++i) {
            result = this->read<uint64_t>(result + offsets[i]);
            if (!is_valid_address(result)) return {};
        }
        return this->read<T>(result + offsets.back());
    }

    template <typename T>
    bool write(uint64_t address, T value, uint32_t process_id = 0) const {
        return this->write(address, &value, sizeof(T), process_id);
    }

private:
    const DMA& dma;
    const uint32_t process_id;
};