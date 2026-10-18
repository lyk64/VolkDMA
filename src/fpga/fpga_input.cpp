#include "src/fpga/fpga.hh"

#include <VolkLog/log.hh>

#include <array>
#include <bitset>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/address.hh"
#include "include/VolkDMA/device.hh"
#include "include/VolkDMA/process.hh"
#include "src/fpga/resource.hh"

namespace volk::dma::fpga {

namespace {

constexpr volk::log::Logger logger{ "dma.inputstate" };

bool is_down_in_win32k_table(std::span<const uint8_t> table, size_t key) {
    const size_t bit = key * 2;
    return (table[bit / 8] >> (bit % 8)) & 1;
}

struct KernelSymbol {
    uint64_t address{};
    std::optional<Process> process;

    [[nodiscard]] bool resolved() const { return is_kernel_address(address) && process.has_value(); }
};

class FpgaInput final : public detail::InputBackend {
public:
    FpgaInput(const Device& dma, VMM_HANDLE vmm) {
        const auto csrss_process_ids = dma.get_process_id_list("csrss.exe");

        if (retrieve_gptCursorAsync(dma, csrss_process_ids)) {
            logger.info("Successfully retrieved gptCursorAsync.");
        }
        else {
            logger.error("Failed to retrieve gptCursorAsync.");
        }

        if (!VMMDLL_ConfigGet(vmm, VMMDLL_OPT_WIN_VERSION_BUILD, &windows_version_build)) {
            logger.error("Failed to retrieve Windows build.");
            return;
        }

        if (retrieve_gafAsyncKeyState(dma, vmm, csrss_process_ids)) {
            logger.info("Successfully retrieved gafAsyncKeyState.");
        }
        else {
            logger.error("Failed to retrieve gafAsyncKeyState.");
        }
    }

    InputState::Point cursor_position() const override {
        if (!gptCursorAsync.resolved()) return {};
        return gptCursorAsync.process->read<InputState::Point>(gptCursorAsync.address);
    }

    std::optional<std::bitset<256>> read_keys() const override {
        if (!gafAsyncKeyState.resolved()) return std::nullopt;

        std::array<uint8_t, 256 * 2 / 8> table{};
        if (!gafAsyncKeyState.process->read(gafAsyncKeyState.address, table.data(), table.size())) return std::nullopt;

        std::bitset<256> keys;
        for (size_t key = 0; key < keys.size(); ++key)
            keys[key] = is_down_in_win32k_table(table, key);
        return keys;
    }

private:
    uint64_t windows_version_build{};

    KernelSymbol gptCursorAsync;
    KernelSymbol gafAsyncKeyState;

    [[nodiscard]] bool retrieve_gafAsyncKeyState(const Device& dma, VMM_HANDLE vmm, const std::vector<uint32_t>& csrss_process_ids) {
        if (windows_version_build > 22000) {
            if (csrss_process_ids.empty()) {
                logger.error("No csrss.exe processes found.");
                return false;
            }

            for (const uint32_t process_id : csrss_process_ids) {
                detail::Resource<VMMDLL_MAP_MODULEENTRY> win32k_module_info{};
                std::string_view win32k_module_name;
                if (VMMDLL_Map_GetModuleFromNameU(vmm, process_id, "win32ksgd.sys", win32k_module_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                    win32k_module_name = "win32ksgd.sys";
                }
                else if (VMMDLL_Map_GetModuleFromNameU(vmm, process_id, "win32k.sys", win32k_module_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                    win32k_module_name = "win32k.sys";
                }
                else {
                    logger.error("Failed to find win32ksgd.sys or win32k.sys for csrss.exe (PID: {}).", process_id);
                    continue;
                }

                const Process csrss_process(dma, process_id);

                uint64_t g_session_address = csrss_process.find_signature("48 8B 05 ? ? ? ? 48 8B 04 C8", win32k_module_info->vaBase, win32k_module_info->vaBase + win32k_module_info->cbImageSize);
                if (!g_session_address)
                    g_session_address = csrss_process.find_signature("48 8B 05 ? ? ? ? FF C9", win32k_module_info->vaBase, win32k_module_info->vaBase + win32k_module_info->cbImageSize);

                if (!g_session_address) {
                    logger.error("Failed to find signature in {} for csrss.exe (PID: {}).", win32k_module_name, process_id);
                    continue;
                }

                uint64_t user_session_state = 0;
                for (int i = 0; i < 4; i++) {
                    user_session_state = csrss_process.read<uint64_t>(csrss_process.read<uint64_t>(csrss_process.read<uint64_t>(g_session_address + 7 + csrss_process.read<int>(g_session_address + 3)) + 8 * i));
                    if (is_kernel_address(user_session_state))
                        break;
                }

                detail::Resource<VMMDLL_MAP_MODULEENTRY> win32kbase_info{};
                if (!VMMDLL_Map_GetModuleFromNameU(vmm, process_id, "win32kbase.sys", win32kbase_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                    logger.error("Failed to find win32kbase.sys for csrss.exe (PID: {}).", process_id);
                    continue;
                }

                uint64_t sig_ptr = csrss_process.find_signature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0", win32kbase_info->vaBase, win32kbase_info->vaBase + win32kbase_info->cbImageSize);
                if (!sig_ptr) {
                    logger.error("Failed to find signature in win32kbase.sys for csrss.exe (PID: {}).", process_id);
                    continue;
                }

                const uint64_t address = user_session_state + csrss_process.read<uint32_t>(sig_ptr + 3);
                if (!is_kernel_address(address)) continue;

                gafAsyncKeyState.address = address;
                gafAsyncKeyState.process.emplace(csrss_process);
                return true;
            }

            return false;
        }

        const std::optional<uint32_t> winlogon_process_id = dma.get_process_id("winlogon.exe");
        if (!winlogon_process_id) {
            logger.error("Failed to get process ID for winlogon.exe.");
            return false;
        }

        const Process winlogon_process(dma, *winlogon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY);

        const uint64_t address = winlogon_process.get_export("win32kbase.sys", "gafAsyncKeyState");
        if (!is_kernel_address(address)) return false;

        gafAsyncKeyState.address = address;
        gafAsyncKeyState.process.emplace(winlogon_process);
        return true;
    }

    [[nodiscard]] bool retrieve_gptCursorAsync(const Device& dma, const std::vector<uint32_t>& csrss_process_ids) {
        if (csrss_process_ids.empty()) {
            logger.error("No csrss.exe processes found.");
            return false;
        }

        for (const uint32_t process_id : csrss_process_ids) {
            const Process candidate_process(dma, process_id);

            const uint64_t address = candidate_process.get_export("win32kbase.sys", "gptCursorAsync");
            if (!is_kernel_address(address)) continue;

            const InputState::Point position = candidate_process.read<InputState::Point>(address);
            if ((position.x == 0 && position.y == 0) || (position.x == 512 && position.y == 384)) continue;

            gptCursorAsync.address = address;
            gptCursorAsync.process.emplace(candidate_process);
            return true;
        }

        return false;
    }
};

} // namespace

std::unique_ptr<detail::InputBackend> open_input(const Device& device, VMM_HANDLE vmm) {
    return std::make_unique<FpgaInput>(device, vmm);
}

} // namespace volk::dma::fpga
