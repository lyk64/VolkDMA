#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <vector>

class DMA;

using DWORD = unsigned long;

class InputState {
public:
    explicit InputState(const DMA& dma);

    struct Point {
        int32_t x;
        int32_t y;
    };

    [[nodiscard]] Point get_cursor_position() const;

    bool read_bitmap();
    [[nodiscard]] bool is_key_held(uint8_t virtual_key_code) const;
    [[nodiscard]] bool is_key_pressed(uint8_t virtual_key_code) const;
    void print_down_keys() const;

    struct VirtualKey {
        uint8_t code;
        std::string_view name;
    };

    inline static constexpr std::array<VirtualKey, 156> virtual_keys = {{
        {0x01, "Left Mouse Button"},
        {0x02, "Right Mouse Button"},
        {0x03, "Control-break Processing"},
        {0x04, "Middle Mouse Button"},
        {0x05, "X1 Mouse Button"},
        {0x06, "X2 Mouse Button"},
        {0x08, "Backspace"},
        {0x09, "Tab"},
        {0x0C, "Clear"},
        {0x0D, "Enter"},
        {0x10, "Shift"},
        {0x11, "Control"},
        {0x12, "Alt"},
        {0x13, "Pause"},
        {0x14, "Caps Lock"},
        {0x15, "IME Kana/Hangul"},
        {0x16, "IME On"},
        {0x17, "IME Junja"},
        {0x18, "IME Final"},
        {0x19, "IME Hanja/Kanji"},
        {0x1A, "IME Off"},
        {0x1B, "Escape"},
        {0x1C, "IME Convert"},
        {0x1D, "IME Nonconvert"},
        {0x1E, "IME Accept"},
        {0x1F, "IME Mode Change"},
        {0x20, "Spacebar"},
        {0x21, "Page Up"},
        {0x22, "Page Down"},
        {0x23, "End"},
        {0x24, "Home"},
        {0x25, "Left Arrow"},
        {0x26, "Up Arrow"},
        {0x27, "Right Arrow"},
        {0x28, "Down Arrow"},
        {0x29, "Select"},
        {0x2A, "Print"},
        {0x2B, "Execute"},
        {0x2C, "Print Screen"},
        {0x2D, "Insert"},
        {0x2E, "Delete"},
        {0x2F, "Help"},
        {0x30, "0"},
        {0x31, "1"},
        {0x32, "2"},
        {0x33, "3"},
        {0x34, "4"},
        {0x35, "5"},
        {0x36, "6"},
        {0x37, "7"},
        {0x38, "8"},
        {0x39, "9"},
        {0x41, "A"},
        {0x42, "B"},
        {0x43, "C"},
        {0x44, "D"},
        {0x45, "E"},
        {0x46, "F"},
        {0x47, "G"},
        {0x48, "H"},
        {0x49, "I"},
        {0x4A, "J"},
        {0x4B, "K"},
        {0x4C, "L"},
        {0x4D, "M"},
        {0x4E, "N"},
        {0x4F, "O"},
        {0x50, "P"},
        {0x51, "Q"},
        {0x52, "R"},
        {0x53, "S"},
        {0x54, "T"},
        {0x55, "U"},
        {0x56, "V"},
        {0x57, "W"},
        {0x58, "X"},
        {0x59, "Y"},
        {0x5A, "Z"},
        {0x5B, "Left Windows"},
        {0x5C, "Right Windows"},
        {0x5D, "Applications"},
        {0x5F, "Sleep"},
        {0x60, "Numpad 0"},
        {0x61, "Numpad 1"},
        {0x62, "Numpad 2"},
        {0x63, "Numpad 3"},
        {0x64, "Numpad 4"},
        {0x65, "Numpad 5"},
        {0x66, "Numpad 6"},
        {0x67, "Numpad 7"},
        {0x68, "Numpad 8"},
        {0x69, "Numpad 9"},
        {0x6A, "Numpad *"},
        {0x6B, "Numpad +"},
        {0x6C, "Numpad Separator"},
        {0x6D, "Numpad -"},
        {0x6E, "Numpad ."},
        {0x6F, "Numpad /"},
        {0x70, "F1"},
        {0x71, "F2"},
        {0x72, "F3"},
        {0x73, "F4"},
        {0x74, "F5"},
        {0x75, "F6"},
        {0x76, "F7"},
        {0x77, "F8"},
        {0x78, "F9"},
        {0x79, "F10"},
        {0x7A, "F11"},
        {0x7B, "F12"},
        {0x7C, "F13"},
        {0x7D, "F14"},
        {0x7E, "F15"},
        {0x7F, "F16"},
        {0x80, "F17"},
        {0x81, "F18"},
        {0x82, "F19"},
        {0x83, "F20"},
        {0x84, "F21"},
        {0x85, "F22"},
        {0x86, "F23"},
        {0x87, "F24"},
        {0x90, "Num Lock"},
        {0x91, "Scroll Lock"},
        {0xA0, "Left Shift"},
        {0xA1, "Right Shift"},
        {0xA2, "Left Control"},
        {0xA3, "Right Control"},
        {0xA4, "Left Alt"},
        {0xA5, "Right Alt"},
        {0xA6, "Browser Back"},
        {0xA7, "Browser Forward"},
        {0xA8, "Browser Refresh"},
        {0xA9, "Browser Stop"},
        {0xAA, "Browser Search"},
        {0xAB, "Browser Favorites"},
        {0xAC, "Browser Home"},
        {0xAD, "Volume Mute"},
        {0xAE, "Volume Down"},
        {0xAF, "Volume Up"},
        {0xB0, "Next Track"},
        {0xB1, "Previous Track"},
        {0xB2, "Stop Media"},
        {0xB3, "Play/Pause"},
        {0xBA, "Semicolon"},
        {0xBB, "Equals"},
        {0xBC, "Comma"},
        {0xBD, "Minus"},
        {0xBE, "Period"},
        {0xBF, "Forward Slash"},
        {0xC0, "Grave Accent"},
        {0xDB, "Left Bracket"},
        {0xDC, "Backslash"},
        {0xDD, "Right Bracket"},
        {0xDE, "Single Quote"},
        {0xFF, "System Quirk (often Pause or Print Screen)"},
    }};

private:
    const DMA& dma;

    uint64_t windows_version_build{};

    DWORD gptCursorAsync_process_id{};
    uint64_t gptCursorAsync_address{};

    DWORD winlogon_process_id{};
    uint64_t gafAsyncKeyState_address{};
    std::array<uint8_t, 64> state_bitmap{};
    std::array<uint8_t, 64> prev_bitmap{};

    [[nodiscard]] bool get_bit(const std::array<uint8_t, 64>& bitmap, uint8_t virtual_key_code) const;
    [[nodiscard]] bool retrieve_gafAsyncKeyState(const std::vector<DWORD>& csrss_process_ids);
    [[nodiscard]] bool retrieve_gptCursorAsync(const std::vector<DWORD>& csrss_process_ids);
};
