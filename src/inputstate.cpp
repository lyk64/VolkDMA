#include "include/VolkDMA/inputstate.hh"

#include <VolkLog/log.hh>

#include <atomic>
#include <optional>

#include "include/VolkDMA/coroutine.hh"
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

std::optional<detail::KeyTable> InputState::key_table() {
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

Task update_input(InputState& input_state) {
    const auto table = input_state.key_table();
    if (!table || !IoContext::current().options.kernel_memory) {
        static std::atomic<bool> warned{ false };
        if (table && !warned.exchange(true))
            logger.warn("The IoContext has no kernel memory, so keys are read with a blocking read instead of in the frame's wave.");
        input_state.read_bitmap();
        co_return;
    }

    Gather g;
    g.read(table->address, table->buffer);
    co_await g;
    input_state.apply_gathered();
}

} // namespace volk::dma
