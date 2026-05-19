#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class DMA;
using VMMDLL_SCATTER_HANDLE = void*;

class Process {
public:
    Process(DMA& dma, const std::string& process_name);
    [[nodiscard]] uint64_t get_base_address(const std::string& module_name) const;
    [[nodiscard]] size_t get_size(const std::string& module_name) const;
    bool dump_module(const std::string& module_name, const std::string& path) const;
    [[nodiscard]] std::string get_path(const std::string& module_name) const;
    [[nodiscard]] std::vector<std::string> get_modules(uint32_t process_id = 0) const;
    bool fix_cr3(const std::string& process_name);
    [[nodiscard]] bool is_valid_address(uint64_t address) const noexcept { return address >= 0x1000; }
    bool virtual_to_physical(uint64_t virtual_address, uint64_t& physical_address) const;
    bool read(uint64_t address, void* buffer, size_t size) const;
    [[nodiscard]] uint64_t read_chain(uint64_t base, const std::vector<uint64_t>& offsets) const;
    [[nodiscard]] bool write(uint64_t address, void* buffer, size_t size, uint32_t process_id = 0) const;
    [[nodiscard]] VMMDLL_SCATTER_HANDLE create_scatter(uint32_t process_id = 0) const;
    void close_scatter(VMMDLL_SCATTER_HANDLE scatter_handle) const;
    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, void* buffer, size_t size) const;
    bool execute_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint32_t process_id = 0) const;

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
        }
        return this->read<T>(result + offsets.back());
    }

    template <typename T>
    bool write(uint64_t address, T value, uint32_t process_id = 0) const {
        return this->write(address, &value, sizeof(T), process_id);
    }

    template <typename T>
    bool add_read_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, T* buffer) const {
        return this->add_read_scatter(scatter_handle, address, reinterpret_cast<void*>(buffer), sizeof(T));
    }

    template <typename T>
    bool add_write_scatter(VMMDLL_SCATTER_HANDLE scatter_handle, uint64_t address, const T& value) const {
        return this->add_write_scatter(scatter_handle, address, reinterpret_cast<void*>(const_cast<T*>(&value)), sizeof(T));
    }

private:
    const DMA& dma;
    const uint32_t process_id;
    
    mutable std::unordered_map<VMMDLL_SCATTER_HANDLE, int> scatter_counts;
};