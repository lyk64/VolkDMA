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
    return update(backend->read_keys());
}

std::optional<InputState::KeyTable> InputState::key_table() {
    return backend->key_table();
}

bool InputState::apply_gathered() {
    return update(backend->gathered_keys());
}

bool InputState::update(const std::optional<Keys>& read) {
    previous_keys = keys;
    keys = read.value_or(Keys{});
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
