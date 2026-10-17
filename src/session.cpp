#include "include/VolkDMA/session.hh"
#include "include/VolkDMA/dma.hh"

#include <VolkLog/log.hh>

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>

namespace volk::dma {

static constexpr volk::log::Logger logger{ "dma.session" };

namespace {

void sleep_for(std::stop_token stop_token, std::chrono::milliseconds duration) {
    std::mutex mutex;
    std::condition_variable_any cv;
    std::unique_lock lock(mutex);
    cv.wait_for(lock, stop_token, duration, [] { return false; });
}

bool is_live(const Device& dma, const std::string& process_name, const Process& process) {
    const std::optional<uint32_t> current = dma.get_process_id(process_name);
    if (current == process.id()) {
        return true;
    }

    if (current) {
        logger.debug("{} now resolves to PID {}, not {}.", process_name, *current, process.id());
    } else {
        logger.debug("{} (PID {}) is no longer listed.", process_name, process.id());
    }
    return false;
}

bool wait_for_module(const Device& dma, const std::string& process_name, const Process& process, std::stop_token stop_token, const SessionOptions& options) {
    if (options.required_module.empty()) {
        return true;
    }

    bool waiting_logged = false;
    while (!stop_token.stop_requested()) {
        if (std::ranges::contains(process.get_modules(), options.required_module)) {
            return true;
        }

        if (!is_live(dma, process_name, process)) {
            return false;
        }

        if (!std::exchange(waiting_logged, true)) {
            logger.info("Waiting for {} to load {}.", process_name, options.required_module);
        }
        sleep_for(stop_token, options.poll_interval);
    }

    return false;
}

} // namespace

void run_sessions(std::stop_token stop_token, const Device& dma, const std::string& process_name, SessionFn session, const SessionOptions& options) {
    std::optional<AttachError> last_error;

    while (!stop_token.stop_requested()) {
        auto process = Process::attach(dma, process_name, {}, stop_token);
        if (!process) {
            if (stop_token.stop_requested()) {
                break;
            }
            if (last_error != process.error()) {
                logger.info("Waiting for {} ({}).", process_name, to_string(process.error()));
                last_error = process.error();
            }
            sleep_for(stop_token, options.poll_interval);
            continue;
        }
        last_error.reset();

        if (!wait_for_module(dma, process_name, *process, stop_token, options)) {
            continue;
        }

        logger.info("Session started for {}.", process_name);

        std::stop_source session_stop;
        const std::stop_callback forward_stop(stop_token, [&] { session_stop.request_stop(); });

        std::jthread exit_watch([&](std::stop_token watch_token) {
            while (!watch_token.stop_requested()) {
                sleep_for(watch_token, options.poll_interval);
                if (!watch_token.stop_requested() && !is_live(dma, process_name, *process)) {
                    logger.info("{} exited.", process_name);
                    session_stop.request_stop();
                    return;
                }
            }
        });

        session(*process, session_stop.get_token());

        logger.info("Session ended for {}.", process_name);
    }
}

} // namespace volk::dma
