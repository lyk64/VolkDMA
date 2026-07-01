#include "include/VolkDMA/inputstate.hh"

#include <VolkLog/log.hh>

#include <span>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/dma.hh"
#include "include/VolkDMA/internal/volkresource.hh"
#include "include/VolkDMA/process.hh"

static constexpr Volk::Log::Logger logger{ "INPUTSTATE" };

[[nodiscard]] static constexpr bool is_kernel_address(uint64_t address) noexcept {
    return (address >> 47) == 0x1FFFFULL;
}

InputState::InputState(const DMA& dma) : dma(dma) {
    const auto csrss_process_ids = dma.get_process_id_list("csrss.exe");

    if (retrieve_gptCursorAsync(csrss_process_ids)) {
        logger.info("Successfully retrieved gptCursorAsync.");
    }
    else {
        logger.error("Failed to retrieve gptCursorAsync.");
    }

    if (!VMMDLL_ConfigGet(dma.get_handle(), VMMDLL_OPT_WIN_VERSION_BUILD, &windows_version_build)) {
        logger.error("Failed to retrieve Windows build.");
        return;
    }

    if (retrieve_gafAsyncKeyState(csrss_process_ids)) {
        logger.info("Successfully retrieved gafAsyncKeyState.");
    }
    else {
        logger.error("Failed to retrieve gafAsyncKeyState.");
    }
}

bool InputState::retrieve_gafAsyncKeyState(const std::vector<uint32_t>& csrss_process_ids) {
    winlogon_process_id = dma.get_process_id("winlogon.exe");
    if (!winlogon_process_id) {
        logger.error("Failed to get process ID for winlogon.exe.");
        return false;
    }

    if (windows_version_build > 22000) {
        if (csrss_process_ids.empty()) {
            logger.error("No csrss.exe processes found.");
            return false;
        }

        for (const uint32_t process_id : csrss_process_ids) {
            VolkResource<VMMDLL_MAP_MODULEENTRY> win32k_module_info{};
            std::string_view win32k_module_name;
            if (VMMDLL_Map_GetModuleFromNameU(dma.get_handle(), process_id, "win32ksgd.sys", win32k_module_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                win32k_module_name = "win32ksgd.sys";
            }
            else if (VMMDLL_Map_GetModuleFromNameU(dma.get_handle(), process_id, "win32k.sys", win32k_module_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                win32k_module_name = "win32k.sys";
            }
            else {
                logger.error("Failed to find win32ksgd.sys or win32k.sys for csrss.exe (PID: {}).", process_id);
                continue;
            }

            uint64_t g_session_address = dma.find_signature("48 8B 05 ? ? ? ? 48 8B 04 C8", win32k_module_info->vaBase, win32k_module_info->vaBase + win32k_module_info->cbImageSize, process_id);
            if (!g_session_address)
                g_session_address = dma.find_signature("48 8B 05 ? ? ? ? FF C9", win32k_module_info->vaBase, win32k_module_info->vaBase + win32k_module_info->cbImageSize, process_id);

            if (!g_session_address) {
                logger.error("Failed to find signature in {} for csrss.exe (PID: {}).", win32k_module_name, process_id);
                continue;
            }

            const Process csrss_process(dma, process_id);

            uint64_t user_session_state = 0;
            for (int i = 0; i < 4; i++) {
                user_session_state = csrss_process.read<uint64_t>(csrss_process.read<uint64_t>(csrss_process.read<uint64_t>(g_session_address + 7 + csrss_process.read<int>(g_session_address + 3)) + 8 * i));
                if (is_kernel_address(user_session_state))
                    break;
            }

            VolkResource<VMMDLL_MAP_MODULEENTRY> win32kbase_info{};
            if (!VMMDLL_Map_GetModuleFromNameU(dma.get_handle(), process_id, "win32kbase.sys", win32kbase_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                logger.error("Failed to find win32kbase.sys for csrss.exe (PID: {}).", process_id);
                continue;
            }

            uint64_t sig_ptr = dma.find_signature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0", win32kbase_info->vaBase, win32kbase_info->vaBase + win32kbase_info->cbImageSize, process_id);
            if (!sig_ptr) {
                logger.error("Failed to find signature in win32kbase.sys for csrss.exe (PID: {}).", process_id);
                continue;
            }

            gafAsyncKeyState_address = user_session_state + csrss_process.read<uint32_t>(sig_ptr + 3);

            if (is_kernel_address(gafAsyncKeyState_address)) {
                return true;
            }
        }

        return false;
    }

    // windows_version_build <= 22000
    VolkResource<VMMDLL_MAP_EAT> eat_map{};
    if (!VMMDLL_Map_GetEATU(dma.get_handle(), winlogon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, "win32kbase.sys", eat_map.out()) || eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
        logger.error("Failed to retrieve EAT map in win32kbase.sys for winlogon.exe (PID: {}).", winlogon_process_id);
        return false;
    }

    for (auto& entry : std::span(eat_map->pMap, eat_map->cMap)) {
        if (!entry.uszFunction) continue;
        if (std::string_view(entry.uszFunction) != "gafAsyncKeyState") continue;
        gafAsyncKeyState_address = entry.vaFunction;
        break;
    }

    return is_kernel_address(gafAsyncKeyState_address);
}

bool InputState::retrieve_gptCursorAsync(const std::vector<uint32_t>& csrss_process_ids) {
    if (csrss_process_ids.empty()) {
        logger.error("No csrss.exe processes found.");
        return false;
    }

    for (const uint32_t process_id : csrss_process_ids) {
        if (gptCursorAsync_address) break;

        VolkResource<VMMDLL_MAP_EAT> eat_map{};
        if (!VMMDLL_Map_GetEATU(dma.get_handle(), process_id, "win32kbase.sys", eat_map.out())) {
            logger.error("Failed to retrieve EAT map in win32kbase.sys for csrss.exe (PID: {}).", process_id);
            continue;
        }

        if (eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
            logger.error("EAT version mismatch for csrss.exe (PID: {}): got {}.", process_id, eat_map->dwVersion);
            continue;
        }

        const Process candidate_process(dma, process_id);

        for (auto& entry : std::span(eat_map->pMap, eat_map->cMap)) {
            if (!entry.uszFunction) continue;

            std::string_view export_function_name(entry.uszFunction);
            if (export_function_name.find("gptCursorAsync") == std::string::npos) continue;

            Point position = candidate_process.read<Point>(entry.vaFunction);

            if (((position.x == 0 && position.y == 0) || (position.x == 512 && position.y == 384))) continue;

            gptCursorAsync_address = entry.vaFunction;
            gptCursorAsync_process.emplace(dma, process_id);
            break;
        }
    }

    return gptCursorAsync_address != 0 && gptCursorAsync_process.has_value();
}

InputState::Point InputState::get_cursor_position() const {
    return gptCursorAsync_process->read<Point>(gptCursorAsync_address);
}

bool InputState::read_bitmap() {
    prev_bitmap = state_bitmap;
    return VMMDLL_MemReadEx(dma.get_handle(), winlogon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, gafAsyncKeyState_address, reinterpret_cast<PBYTE>(&state_bitmap), static_cast<DWORD>(sizeof(state_bitmap)), nullptr, VMMDLL_FLAG_NOCACHE);
}

bool InputState::get_bit(const std::array<uint8_t, 64>& bitmap, uint8_t virtual_key_code) const {
    const int bit_index = virtual_key_code * 2;
    return (bitmap[bit_index / 8] & (1 << (bit_index % 8))) != 0;
}

bool InputState::is_key_held(uint8_t virtual_key_code) const {
    return get_bit(state_bitmap, virtual_key_code);
}

bool InputState::is_key_pressed(uint8_t virtual_key_code) const {
    return get_bit(state_bitmap, virtual_key_code) && !get_bit(prev_bitmap, virtual_key_code);
}

void InputState::print_down_keys() const {
    for (const auto& [code, name] : virtual_keys) {
        if (is_key_held(code)) {
            logger.debug("Key down: {}.", name);
        }
    }
}