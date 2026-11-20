#pragma once

#include <type_traits>

namespace volk::dma {

template <typename T>
concept TriviallyCopyable = std::is_trivially_copyable_v<T>;

} // namespace volk::dma
