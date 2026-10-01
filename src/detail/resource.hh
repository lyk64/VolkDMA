#pragma once

extern "C" void VMMDLL_MemFree(void*);

namespace volk::dma::detail {

template <class T>
class Resource {
public:
    Resource() = default;
    explicit Resource(T* p) : p_(p) {}
    ~Resource() { reset(); }

    Resource(const Resource&) = delete;
    Resource& operator=(const Resource&) = delete;

    Resource(Resource&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    Resource& operator=(Resource&& o) noexcept {
        if (this != &o) { reset(); p_ = o.p_; o.p_ = nullptr; }
        return *this;
    }

    T** out() { reset(); return &p_; }
    T* get() const { return p_; }
    T& operator*() const { return *p_; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
    void reset(T* np = nullptr) {
        if (p_) VMMDLL_MemFree(p_);
        p_ = np;
    }
    T* release() { T* r = p_; p_ = nullptr; return r; }

private:
    T* p_ = nullptr;
};

} // namespace volk::dma::detail
