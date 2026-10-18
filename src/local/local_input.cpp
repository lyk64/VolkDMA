#include "src/local/local.hh"

#include <bitset>
#include <optional>

namespace volk::dma::local {

namespace {

class LocalInput final : public detail::InputBackend {
public:
    InputState::Point cursor_position() const override {
        POINT position{};
        if (!GetCursorPos(&position)) {
            return {};
        }

        return { position.x, position.y };
    }

    std::optional<std::bitset<256>> read_keys() const override {
        std::bitset<256> keys;
        for (int key = 0; key < 256; ++key)
            keys[key] = (GetAsyncKeyState(key) & 0x8000) != 0;
        return keys;
    }
};

} // namespace

std::unique_ptr<detail::InputBackend> open_input() {
    return std::make_unique<LocalInput>();
}

} // namespace volk::dma::local
