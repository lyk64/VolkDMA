#include "include/VolkDMA/profiler.hh"

#ifdef _DEBUG

#include <VolkLog/log.hh>

#include <algorithm>
#include <functional>
#include <ranges>
#include <utility>

namespace volk::dma::profiler {

static constexpr volk::log::Logger logger{ "dma.profiler" };

void FrameStats::skip_frame(std::vector<WaveReport> pumps) {
    if (enabled.load(std::memory_order_relaxed)) publish(pumps);
}

void FrameStats::end_frame(std::vector<WaveReport> pumps) {
    if (!enabled.load(std::memory_order_relaxed)) return;

    const uint32_t frame_waves = std::ranges::fold_left(pumps | std::views::transform(&WaveReport::waves), 0u, std::plus{});
    publish(pumps);

    const auto now = std::chrono::steady_clock::now();
    if (now - interval_end > length) {
        interval_end = now + length;
        frames = waves = multi_wave_frames = 0;
        worst_waves = 0;
        reset();
    }

    ++frames;
    waves += frame_waves;
    if (frame_waves > 1) ++multi_wave_frames;
    worst_waves = (std::max)(worst_waves, frame_waves);

    if (now < interval_end) return;
    interval_end = now + length;

    IntervalReport report{
        .frames = frames,
        .waves_per_frame = static_cast<double>(waves) / frames,
        .multi_wave_percent = 100.0 * multi_wave_frames / frames,
        .worst_waves = worst_waves,
    };
    frames = waves = multi_wave_frames = 0;
    worst_waves = 0;

    logger.info("{} frames, {:.3f} waves/frame, {:.1f}% multi-wave, worst {}.", report.frames, report.waves_per_frame, report.multi_wave_percent, report.worst_waves);

    report.ops = drain();
    std::ranges::sort(report.ops, std::greater{}, [&](const Timing& timing) { return report.ms_per_frame(timing); });
    for (const auto& timing : report.ops)
        logger.info("{}: {} calls, {:.3f} ms/frame, avg {:.3f} ms, worst {:.3f} ms.", timing.name, timing.calls, report.ms_per_frame(timing), timing.average_ms, timing.worst_ms);

    interval_report.store(std::make_shared<const IntervalReport>(std::move(report)), std::memory_order_release);
}

void FrameStats::publish(std::vector<WaveReport>& pumps) {
    if (peak_reset_requested.exchange(false, std::memory_order_relaxed)) {
        peak_waves = 0;
        peak_report.store(std::make_shared<const WaveReport>(), std::memory_order_release);
    }

    if (pumps.empty()) return;

    const WaveReport* deepest = &pumps.front();
    for (const auto& pump : pumps)
        if (pump.waves >= deepest->waves) deepest = &pump;

    if (deepest->waves >= peak_waves) {
        peak_waves = deepest->waves;
        peak_report.store(std::make_shared<const WaveReport>(*deepest), std::memory_order_release);
    }
    last_report.store(std::make_shared<const WaveReport>(std::move(pumps.back())), std::memory_order_release);
}

} // namespace volk::dma::profiler

#endif
