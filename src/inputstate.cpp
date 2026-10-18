#include "include/VolkDMA/inputstate.hh"

#include <VolkLog/log.hh>

#include <optional>

#include "include/VolkDMA/device.hh"
#include "detail/backend.hh"

namespace volk::dma {

static constexpr volk::log::Logger logger{ "dma.inputstate" };

InputState::InputState(const Device& dma) : backend(dma.backend->create_input(dma)) {}

InputState::~InputState() = default;

InputState::InputState(InputState&& other) noexcept = default;

InputState& InputState::operator=(InputState&& other) noexcept = default;

InputState::Point InputState::get_cursor_position() const {
    return backend->cursor_position();
}

bool InputState::read_bitmap() {
    previous_keys = keys;
    const std::optional<std::bitset<256>> read = backend->read_keys();
    keys = read.value_or(std::bitset<256>{});
    return read.has_value();
}

bool InputState::is_key_held(uint8_t virtual_key_code) const {
    return keys.test(virtual_key_code);
}

bool InputState::is_key_pressed(uint8_t virtual_key_code) const {
    return keys.test(virtual_key_code) && !previous_keys.test(virtual_key_code);
}

void InputState::print_down_keys() const {
    for (const auto& [code, name] : virtual_keys) {
        if (is_key_held(code)) {
            logger.debug("Key down: {}.", name);
        }
    }
}

} // namespace volk::dma
