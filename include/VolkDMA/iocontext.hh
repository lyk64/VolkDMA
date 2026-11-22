#pragma once

#include <cassert>
#include <coroutine>
#include <cstdint>
#include <utility>
#include <vector>

#include "concepts.hh"
#include "process.hh"
#include "profiler.hh"
#include "scatter.hh"

namespace volk::dma {

namespace detail {

template <class T>
struct ReadAwaiter;

template <class T>
struct ReadArrayAwaiter;

} // namespace detail

class Gather;

template <TriviallyCopyable T>
bool write(uint64_t address, const T& value);

struct IoContextOptions {
    bool kernel_memory{};
};

class IoContext {
public:
    class Binding;

    explicit IoContext(const Process& process, IoContextOptions options = {})
        : process(process), options(options), scatter(this->process.create_scatter({ .kernel_memory = options.kernel_memory })) {}

    IoContext(const IoContext&) = delete;
    IoContext& operator=(const IoContext&) = delete;

    [[nodiscard]] bool idle() const noexcept { return pending.empty(); }

    [[nodiscard]] profiler::WaveRecorder& waves() noexcept { return recorder; }

    void pump(profiler::Location caller = profiler::Location::current()) {
        assert(!pumping && "pump() is not reentrant");
        pumping = true;
        recorder.pump_enter();

        while (!pending.empty()) {
            batch.swap(pending);
            scatter.execute(profiler::Location::current(), caller);
            recorder.wave_fired();
            resume_batch();
        }

        recorder.pump_exit();
        pumping = false;
    }

    void flush(profiler::Location caller = profiler::Location::current()) {
        assert(!pumping && "flush() inside pump()");
        assert(idle() && "flush() with reads still waiting; pump() first");
        scatter.execute(caller);
    }

    [[nodiscard]] static IoContext& current() noexcept {
        assert(bound && "No IoContext is bound on this thread");
        return *bound;
    }

    const Process process;
    const IoContextOptions options;

private:
    template <class T>
    friend struct detail::ReadAwaiter;

    template <class T>
    friend struct detail::ReadArrayAwaiter;

    friend class Gather;

    template <TriviallyCopyable T>
    friend bool write(uint64_t address, const T& value);

    template <class... Args>
    bool prepare_read(uint64_t address, Args&&... args) {
        return scatter.prepare_read(address, std::forward<Args>(args)...);
    }

    template <TriviallyCopyable T>
    bool prepare_write(uint64_t address, const T& value) {
        return scatter.prepare_write(address, value);
    }

    void submit(std::coroutine_handle<> h, const profiler::Location& loc, uint32_t reads) {
        recorder.record(loc, reads);
        pending.push_back(h);
    }

    void resume_batch() {
        for (auto h : batch) {
            if (h && !h.done()) h.resume();
        }
        batch.clear();
    }

    Scatter scatter;
    std::vector<std::coroutine_handle<>> pending;
    std::vector<std::coroutine_handle<>> batch;
    [[msvc::no_unique_address]] profiler::WaveRecorder recorder;
    bool pumping = false;

    static constinit inline thread_local IoContext* bound = nullptr;
};

class IoContext::Binding {
public:
    [[nodiscard]] explicit Binding(IoContext& context) noexcept : previous(std::exchange(bound, &context)) {}
    ~Binding() { bound = previous; }

    Binding(const Binding&) = delete;
    Binding& operator=(const Binding&) = delete;

private:
    IoContext* previous;
};

} // namespace volk::dma
