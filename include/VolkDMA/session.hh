#pragma once

#include <chrono>
#include <functional>
#include <stop_token>
#include <string>

#include "process.hh"

namespace volk::dma {

struct SessionOptions {
    std::string required_module{};
    std::chrono::milliseconds poll_interval{ std::chrono::seconds{ 1 } };
};

using SessionFn = std::move_only_function<void(const Process&, std::stop_token)>;

void run_sessions(std::stop_token stop_token, const Device& dma, const std::string& process_name, SessionFn session, const SessionOptions& options = {});

} // namespace volk::dma
