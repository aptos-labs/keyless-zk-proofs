#pragma once

#include <atomic>

namespace aptos
{

class [[nodiscard]] spinlock
{
public:
    using lockable_type = std::atomic_uint;

    [[nodiscard]] constexpr spinlock() noexcept = default;

    spinlock(const spinlock&) noexcept            = delete;
    spinlock& operator=(const spinlock&) noexcept = delete;

    void lock() noexcept
    {
        while (lockable_.exchange(1u, std::memory_order_acquire))
        {
            while (lockable_.load(std::memory_order_relaxed))
            {
            }
        }
    }

    bool try_lock() noexcept
    {
        return lockable_.exchange(1u, std::memory_order_acquire);
    }

    void unlock() noexcept { lockable_.store(0u, std::memory_order_release); }

private:
    std::atomic_uint lockable_{0u};
};

} // namespace aptos
