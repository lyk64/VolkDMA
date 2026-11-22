#pragma once

#include <cassert>
#include <concepts>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "concepts.hh"
#include "iocontext.hh"
#include "profiler.hh"

namespace volk::dma {

namespace detail {

template <class T>
struct TaskResult {
    std::optional<T> value;
    void return_value(T v) { value.emplace(std::move(v)); }
};

template <>
struct TaskResult<void> {
    void return_void() noexcept {}
};

} // namespace detail

template <class T>
class BasicTask {
public:
    struct promise_type : detail::TaskResult<T> {
        std::coroutine_handle<> continuation{};
        bool detached = false;

        BasicTask get_return_object() noexcept {
            return BasicTask{ std::coroutine_handle<promise_type>::from_promise(*this) };
        }

        std::suspend_never initial_suspend() noexcept { return {}; }

        struct FinalAwaiter {
            [[nodiscard]] bool await_ready() const noexcept { return false; }
            std::coroutine_handle<> await_suspend(std::coroutine_handle<promise_type> h) noexcept {
                auto& p = h.promise();
                if (p.continuation) return p.continuation;
                if (p.detached) h.destroy();
                return std::noop_coroutine();
            }
            void await_resume() const noexcept {}
        };
        FinalAwaiter final_suspend() noexcept { return {}; }

        void unhandled_exception() { std::terminate(); }
    };

    explicit BasicTask(std::coroutine_handle<promise_type> h) noexcept : handle(h) {}
    BasicTask(BasicTask&& other) noexcept : handle(std::exchange(other.handle, {})) {}
    BasicTask(const BasicTask&) = delete;
    BasicTask& operator=(const BasicTask&) = delete;
    ~BasicTask() {
        if (!handle) return;
        if (handle.done())
            handle.destroy();
        else
            handle.promise().detached = true;
    }

    [[nodiscard]] bool await_ready() const noexcept { return handle.done(); }
    void await_suspend(std::coroutine_handle<> awaiting) noexcept {
        assert(!handle.promise().continuation && "Task awaited by two coroutines");
        handle.promise().continuation = awaiting;
    }
    T await_resume() {
        if constexpr (!std::is_void_v<T>) return std::move(*handle.promise().value);
    }

private:
    std::coroutine_handle<promise_type> handle;
};

using Task = BasicTask<void>;

template <class T>
using ValueTask = BasicTask<T>;

[[nodiscard]] inline Task when_all(std::vector<Task> tasks) {
    for (auto& task : tasks) co_await task;
}

[[nodiscard]] Task when_all(std::same_as<Task> auto... tasks) {
    (co_await tasks, ...);
}

template <class T>
class Lazy {
public:
    using Resolver = ValueTask<T> (*)(uint64_t);

    Lazy(Resolver resolver, uint64_t address) noexcept : resolver(resolver), address(address) {}
    Lazy(Lazy&& other) noexcept : resolver(other.resolver), address(other.address), value(std::move(other.value)), in_flight(std::exchange(other.in_flight, false)) {
        assert((!in_flight || value) && "Lazy moved while resolving");
    }
    Lazy(const Lazy&) = delete;
    Lazy& operator=(const Lazy&) = delete;
    ~Lazy() { assert((!in_flight || value) && "Lazy destroyed while resolving"); }

    Lazy& operator=(Lazy&& other) noexcept {
        if (this == &other) return *this;
        std::destroy_at(this);
        std::construct_at(this, std::move(other));
        return *this;
    }

    [[nodiscard]] bool ready() const noexcept { return value != nullptr; }
    [[nodiscard]] T& get() noexcept { return *value; }
    [[nodiscard]] const T& get() const noexcept { return *value; }

    struct Awaiter {
        Lazy& self;
        Awaiter* next{};
        std::coroutine_handle<> continuation;

        [[nodiscard]] bool await_ready() const noexcept { return self.ready(); }
        bool await_suspend(std::coroutine_handle<> h) {
            if (!std::exchange(self.in_flight, true)) self.start();
            if (self.ready()) return false;
            continuation = h;
            next = std::exchange(self.waiters, this);
            return true;
        }
        [[nodiscard]] T& await_resume() const noexcept { return self.get(); }
    };
    [[nodiscard]] Awaiter operator co_await() noexcept { return { *this }; }

private:
    Task start() {
        value = std::make_unique<T>(co_await resolver(address));
        auto* node = std::exchange(waiters, nullptr);
        while (node) {
            auto* next = node->next;
            node->continuation.resume();
            node = next;
        }
    }

    Resolver resolver;
    uint64_t address;
    std::unique_ptr<T> value;
    bool in_flight = false;
    Awaiter* waiters{};
};

namespace detail {

template <class T>
struct ReadAwaiter {
    uint64_t address;
    T value{};
    [[msvc::no_unique_address]] profiler::Location loc{};

    [[nodiscard]] bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> h) {
        auto& context = IoContext::current();
        if (!context.prepare_read(address, &value)) return false;
        context.submit(h, loc, 1);
        return true;
    }

    [[nodiscard]] T await_resume() const noexcept { return value; }
};

template <class T>
struct ReadArrayAwaiter {
    uint64_t address;
    size_t count;
    std::vector<T> value;
    [[msvc::no_unique_address]] profiler::Location loc{};

    [[nodiscard]] bool await_ready() const noexcept { return false; }

    bool await_suspend(std::coroutine_handle<> h) {
        auto& context = IoContext::current();
        if (!context.prepare_read(address, value, count)) return false;
        context.submit(h, loc, 1);
        return true;
    }

    [[nodiscard]] std::vector<T> await_resume() { return std::move(value); }
};

} // namespace detail

template <TriviallyCopyable T>
[[nodiscard]] detail::ReadAwaiter<T> read(uint64_t address, profiler::Location loc = profiler::Location::current()) {
    return detail::ReadAwaiter<T>{ .address = address, .loc = loc };
}

template <TriviallyCopyable T>
[[nodiscard]] detail::ReadArrayAwaiter<T> read_array(uint64_t address, size_t count, profiler::Location loc = profiler::Location::current()) {
    return detail::ReadArrayAwaiter<T>{ .address = address, .count = count, .loc = loc };
}

class Gather {
public:
    explicit Gather(profiler::Location loc = profiler::Location::current()) : loc(loc) {}
    Gather(const Gather&) = delete;
    Gather& operator=(const Gather&) = delete;
    Gather(Gather&& other) noexcept : loc(other.loc), pending(std::exchange(other.pending, 0)) {}

    ~Gather() { assert(pending == 0 && "Gather destroyed with unflushed reads"); }

    template <TriviallyCopyable T>
    void read(uint64_t address, T* buffer) {
        if (IoContext::current().prepare_read(address, buffer)) ++pending;
    }

    template <TriviallyCopyable T, size_t N>
    void read(uint64_t address, std::span<T, N> buffer) {
        if (IoContext::current().prepare_read(address, buffer.data(), buffer.size_bytes()))
            ++pending;
    }

    [[nodiscard]] bool await_ready() const noexcept { return pending == 0; }
    void await_suspend(std::coroutine_handle<> h) {
        IoContext::current().submit(h, loc, static_cast<uint32_t>(std::exchange(pending, 0)));
    }
    void await_resume() const noexcept {}

private:
    [[msvc::no_unique_address]] profiler::Location loc;
    size_t pending = 0;
};

#ifndef _DEBUG
static_assert(sizeof(Gather) == sizeof(size_t));
static_assert(sizeof(detail::ReadAwaiter<uint64_t>) == 2 * sizeof(uint64_t));
#endif

template <class T>
concept Gatherable = requires(T& t, Gather& g) {
    { t.gather(g) } -> std::same_as<void>;
};

[[nodiscard]] Gather gathered(Gatherable auto& target, profiler::Location loc = profiler::Location::current()) {
    Gather g{ loc };
    target.gather(g);
    return g;
}

} // namespace volk::dma
