#pragma once

#ifdef _DEBUG

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace volk::dma::profiler {

using Location = std::source_location;

struct Timing {
    std::string name;
    uint64_t calls{};
    double average_ms{};
    double worst_ms{};
};

inline std::atomic<bool> enabled{ false };

[[nodiscard]] constexpr std::string_view short_name(std::string_view signature) noexcept {
    constexpr std::string_view convention{ "__cdecl " };
    if (const size_t at = signature.find(convention); at != std::string_view::npos)
        signature.remove_prefix(at + convention.size());

    size_t end = signature.find('(');
    if (end != std::string_view::npos && signature.substr(0, end).ends_with("operator "))
        end = signature.find('(', end + 1);
    return signature.substr(0, end);
}

namespace detail {

struct Key {
    const char* function;
    const char* file;
    uint32_t line;
    bool operator==(const Key&) const noexcept = default;
};

struct KeyHash {
    size_t operator()(const Key& key) const noexcept {
        return (std::hash<const void*>{}(key.function) * 1099511628211ull + std::hash<const void*>{}(key.file)) * 1099511628211ull + key.line;
    }
};

struct Counters {
    const char* function{};
    const char* caller{};
    const char* origin{};
    uint32_t line{};
    uint64_t calls{};
    uint64_t total_us{};
    uint64_t worst_us{};
};

inline std::mutex counters_mutex;
inline std::unordered_map<Key, Counters, KeyHash> counters;

} // namespace detail

class Timed {
public:
    explicit Timed(Location caller = {}, Location origin = {}, Location self = Location::current()) noexcept : caller(caller), origin(origin), self(self) {}
    Timed(const Timed&) = delete;
    Timed& operator=(const Timed&) = delete;

    ~Timed() {
        if (!enabled.load(std::memory_order_relaxed)) return;

        const auto elapsed = std::chrono::steady_clock::now() - start;
        const auto us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());

        const bool has_caller = caller.line() != 0;
        const bool has_origin = origin.line() != 0;
        const Location& site = has_origin ? origin : has_caller ? caller : self;

        const std::scoped_lock lock{ detail::counters_mutex };
        detail::Counters& counters = detail::counters[{ self.function_name(), site.file_name(), site.line() }];
        if (!counters.function) {
            counters.function = self.function_name();
            counters.line = site.line();
            if (has_caller) counters.caller = caller.function_name();
            if (has_origin) counters.origin = origin.function_name();
        }
        ++counters.calls;
        counters.total_us += us;
        if (us > counters.worst_us) counters.worst_us = us;
    }

private:
    Location caller;
    Location origin;
    Location self;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
};

inline void reset() {
    const std::scoped_lock lock{ detail::counters_mutex };
    detail::counters.clear();
}

[[nodiscard]] inline std::vector<Timing> drain() {
    std::vector<Timing> timings;
    {
        const std::scoped_lock lock{ detail::counters_mutex };

        timings.reserve(detail::counters.size());
        for (const auto& [key, counters] : detail::counters) {
            std::string name{ short_name(counters.function) };
            if (counters.caller && counters.origin)
                name += std::format(" ({} < {}:{})", short_name(counters.caller), short_name(counters.origin), counters.line);
            else if (counters.caller)
                name += std::format(" ({}:{})", short_name(counters.caller), counters.line);

            timings.push_back({
                .name = std::move(name),
                .calls = counters.calls,
                .average_ms = counters.total_us / 1000.0 / counters.calls,
                .worst_ms = counters.worst_us / 1000.0,
            });
        }
        detail::counters.clear();
    }
    std::ranges::sort(timings, {}, &Timing::name);
    return timings;
}

} // namespace volk::dma::profiler

#else

namespace volk::dma::profiler {

struct Location {
    [[nodiscard]] static consteval Location current() noexcept { return {}; }
};

class Timed {
public:
    explicit Timed(Location = {}, Location = {}) noexcept {}
    ~Timed() {}
};

} // namespace volk::dma::profiler

#endif
