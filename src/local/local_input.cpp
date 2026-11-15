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

    std::optional<InputState::Keys> read_keys() const override {
        InputState::Keys keys;
        for (size_t key = 0; key < keys.size(); ++key)
            keys[key] = (GetAsyncKeyState(static_cast<int>(key)) & 0x8000) != 0;
        return keys;
    }

    std::optional<InputState::KeyTable> key_table() override {
        return std::nullopt;
    }

    std::optional<InputState::Keys> gathered_keys() const override {
        return std::nullopt;
    }
};

} // namespace

std::unique_ptr<detail::InputBackend> open_input() {
    return std::make_unique<LocalInput>();
}

} // namespace volk::dma::local
