#pragma once

#include <cstddef>
#include <new>
#include <memory>
#include <string>
#include <vector>
#include <cstring>

#if defined(__unix__) || defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace vx::core {

/**
 * @brief SecureAllocator locks pages into RAM via mlock(), prohibits core dumps
 * via MADV_DONTDUMP, and securely wipes memory using explicit_bzero upon deallocation.
 */
template <typename T>
class SecureAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    constexpr SecureAllocator() noexcept = default;

    template <typename U>
    constexpr SecureAllocator(const SecureAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(size_type n) {
        if (n == 0) return nullptr;
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_array_new_length();

        size_type bytes = n * sizeof(T);

#if defined(__linux__)
        void* ptr = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
        if (ptr == MAP_FAILED) {
            // Fallback to posix_memalign if mmap/mlock limit reached
            void* fallback_ptr = nullptr;
            if (::posix_memalign(&fallback_ptr, 64, bytes) != 0 || !fallback_ptr) {
                throw std::bad_alloc();
            }
            ::mlock(fallback_ptr, bytes);
            ptr = fallback_ptr;
        }
        ::madvise(ptr, bytes, MADV_DONTDUMP);
        return static_cast<T*>(ptr);
#else
        void* ptr = ::operator new(bytes);
        return static_cast<T*>(ptr);
#endif
    }

    void deallocate(T* p, size_type n) noexcept {
        if (!p) return;
        size_type bytes = n * sizeof(T);

#if defined(__linux__)
        ::explicit_bzero(p, bytes);
        ::munlock(p, bytes);
        ::munmap(p, bytes);
#else
        std::memset(p, 0, bytes);
        ::operator delete(p);
#endif
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }
    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using SecureByteBuffer = std::vector<uint8_t, SecureAllocator<uint8_t>>;

/**
 * @brief RAII Secure key container that automatically wipes itself upon scope exit.
 */
class SecureKeyBuffer {
public:
    explicit SecureKeyBuffer(size_t size) : m_data(size, 0) {}

    uint8_t* data() noexcept { return m_data.data(); }
    const uint8_t* data() const noexcept { return m_data.data(); }
    size_t size() const noexcept { return m_data.size(); }

    ~SecureKeyBuffer() noexcept {
        if (!m_data.empty()) {
#if defined(__linux__)
            ::explicit_bzero(m_data.data(), m_data.size());
#else
            std::memset(m_data.data(), 0, m_data.size());
#endif
        }
    }

private:
    SecureByteBuffer m_data;
};

} // namespace vx::core
