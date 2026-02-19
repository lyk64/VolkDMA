#include "include/VolkDMA/inputstate.hh"

#include <VolkLog/log.hh>

#include "external/vmm/vmmdll.h"

#include "include/VolkDMA/dma.hh"
#include "include/VolkDMA/internal/volkresource.hh"

static constexpr Volk::Log::Logger logger{ "INPUTSTATE" };

InputState::InputState(const DMA& dma) : dma(dma) {
    const std::vector<DWORD> csrss_process_ids = dma.get_process_id_list("csrss.exe");

    if (retrieve_gptCursorAsync(csrss_process_ids)) {
        logger.info("Successfully retrieved gptCursorAsync.");
    }
    else {
        logger.error("Failed to retrieve gptCursorAsync.");
    }

    if (!VMMDLL_ConfigGet(dma.handle.get(), VMMDLL_OPT_WIN_VERSION_BUILD, &windows_version_build)) {
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

bool InputState::retrieve_gafAsyncKeyState(const std::vector<DWORD>& csrss_process_ids) {
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

        for (const DWORD& process_id : csrss_process_ids) {
            VolkResource<VMMDLL_MAP_MODULEENTRY> win32k_module_info{};
            std::string_view win32k_module_name;
            if (VMMDLL_Map_GetModuleFromNameW(dma.handle.get(), process_id, const_cast<LPWSTR>(L"win32ksgd.sys"), win32k_module_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                win32k_module_name = "win32ksgd.sys";
            }
            else if (VMMDLL_Map_GetModuleFromNameW(dma.handle.get(), process_id, const_cast<LPWSTR>(L"win32k.sys"), win32k_module_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
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

            uint64_t user_session_state = 0;
            for (int i = 0; i < 4; i++) {
                user_session_state = dma.read<uint64_t>(dma.read<uint64_t>(dma.read<uint64_t>(g_session_address + 7 + dma.read<int>(g_session_address + 3, process_id), process_id) + 8 * i, process_id), process_id);
                if (user_session_state > 0x7FFFFFFFFFFF)
                    break;
            }

            VolkResource<VMMDLL_MAP_MODULEENTRY> win32kbase_info{};
            if (!VMMDLL_Map_GetModuleFromNameW(dma.handle.get(), process_id, const_cast<LPWSTR>(L"win32kbase.sys"), win32kbase_info.out(), VMMDLL_MODULE_FLAG_NORMAL)) {
                logger.error("Failed to find win32kbase.sys for csrss.exe (PID: {}).", process_id);
                continue;
            }

            uint64_t sig_ptr = dma.find_signature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0", win32kbase_info->vaBase, win32kbase_info->vaBase + win32kbase_info->cbImageSize, process_id);
            if (!sig_ptr) {
                logger.error("Failed to find signature in win32kbase.sys for csrss.exe (PID: {}).", process_id);
                continue;
            }

            gafAsyncKeyState_address = user_session_state + dma.read<uint32_t>(sig_ptr + 3, process_id);

            if (gafAsyncKeyState_address > 0x7FFFFFFFFFFF) {
                return true;
            }
        }

        return false;
    }

    // windows_version_build <= 22000
    VolkResource<VMMDLL_MAP_EAT> eat_map{};
    if (!VMMDLL_Map_GetEATU(dma.handle.get(), winlogon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), eat_map.out()) || eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
        logger.error("Failed to retrieve EAT map in win32kbase.sys for winlogon.exe (PID: {}).", winlogon_process_id);
        return false;
    }

    for (DWORD i = 0; i < eat_map->cMap; ++i) {
        PVMMDLL_MAP_EATENTRY entry = eat_map->pMap + i;
        if (strcmp(entry->uszFunction, "gafAsyncKeyState") == 0) {
            gafAsyncKeyState_address = entry->vaFunction;
            break;
        }
    }

    return gafAsyncKeyState_address > 0x7FFFFFFFFFFF;
}

bool InputState::retrieve_gptCursorAsync(const std::vector<DWORD>& csrss_process_ids) {
    if (csrss_process_ids.empty()) {
        logger.error("No csrss.exe processes found.");
        return false;
    }

    for (const DWORD& process_id : csrss_process_ids) {
        VolkResource<VMMDLL_MAP_EAT> eat_map;
        if (!VMMDLL_Map_GetEATU(dma.handle.get(), process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, const_cast<LPSTR>("win32kbase.sys"), eat_map.out())) {
            logger.error("Failed to retrieve EAT map in win32kbase.sys for csrss.exe (PID: {}).", process_id);
            continue;
        }

        if (eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION) {
            logger.error("EAT version mismatch for csrss.exe (PID: {}): got {}.", process_id, eat_map->dwVersion);
            continue;
        }

        for (DWORD i = 0; i < eat_map->cMap; ++i) {
            auto& entry = eat_map->pMap[i];

            if (!entry.uszFunction) continue;

            std::string_view export_function_name(entry.uszFunction);
            if (export_function_name.find("gptCursorAsync") == std::string::npos) continue;

            Point position = dma.read<Point>(entry.vaFunction, process_id);

            if (((position.x == 0 && position.y == 0) || (position.x == 512 && position.y == 384))) continue;

            gptCursorAsync_process_id = process_id;
            gptCursorAsync_address = entry.vaFunction;
            break;
        }
    }

    return (gptCursorAsync_address != 0 && gptCursorAsync_process_id != 0);
}

InputState::Point InputState::get_cursor_position() const {
    return dma.read<Point>(gptCursorAsync_address, gptCursorAsync_process_id);
}

bool InputState::read_bitmap() {
    return VMMDLL_MemReadEx(dma.handle.get(), winlogon_process_id | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, gafAsyncKeyState_address, reinterpret_cast<PBYTE>(&state_bitmap), sizeof(state_bitmap), nullptr, VMMDLL_FLAG_NOCACHE);
}

bool InputState::is_key_down(uint8_t virtual_key_code) const {
    constexpr int bits_per_key = 2;
    constexpr int bits_per_byte = 8;

    const int bit_index = virtual_key_code * bits_per_key;
    const int byte_index = bit_index / bits_per_byte;
    const int bit_offset = bit_index % bits_per_byte;

    return (state_bitmap[byte_index] & (1 << bit_offset)) != 0;
}

void InputState::print_down_keys() const {
    for (const auto& [code, name] : virtual_keys) {
        if (is_key_down(code)) {
            logger.debug("Key down: {}.", name);
        }
    }
}