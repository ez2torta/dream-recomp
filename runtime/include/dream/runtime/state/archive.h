// Machine-state serialization (savestate). One Archive drives both directions so a device writes a
// field and reads it back through the same call: `ar.pod(member)`, `ar.vec(member)`, `ar.str(member)`.
// A device's `serialize(Archive&)` has no direction of its own; it calls these and, guarded by
// `ar.loading()`, re-derives whatever a copy cannot carry (pointers, table pointers).
//
// Scope and honesty: this is a workflow accelerator for a deterministic AOT build, not a portable
// save. It assumes the same executable, the same translated code and a little-endian host, and it
// stores the game's own RAM and VRAM, so a state file is a local artefact and never committed.
// Loads are validated by a magic, a format version and a caller-supplied key, and the payload is
// checksummed, so a stale or truncated file is refused rather than half-applied.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

namespace dream::state {

class Archive {
public:
    enum class Mode { Load, Save };

    explicit Archive(Mode mode) : mode_(mode) {}

    bool saving() const noexcept { return mode_ == Mode::Save; }
    bool loading() const noexcept { return mode_ == Mode::Load; }
    bool failed() const noexcept { return failed_; }
    void fail() noexcept { failed_ = true; }
    std::size_t cursor() const noexcept { return cursor_; }
    const std::vector<std::uint8_t>& buffer() const noexcept { return buffer_; }

    // --- primitives -------------------------------------------------------------------------
    // A trivially copyable value (integer, enum, bool, POD struct) as raw bytes. Byte order is the
    // host's, which the header records by refusing to load a state a different build wrote.
    template <class T, std::enable_if_t<!std::is_array_v<T> && std::is_trivially_copyable_v<T>, int> = 0>
    void pod(T& v) {
        raw(&v, sizeof(T));
    }
    // A C array, element by element.
    template <class T, std::size_t N>
    void pod(T (&a)[N]) {
        raw(a, sizeof a);
    }
    // Raw bytes, for a type whose only non-copyable members are re-derived by the caller.
    void raw(void* p, std::size_t n) {
        if (saving()) {
            const auto* b = static_cast<const std::uint8_t*>(p);
            buffer_.insert(buffer_.end(), b, b + n);
            return;
        }
        if (failed_)
            return;
        if (cursor_ + n > buffer_.size()) {
            failed_ = true;
            return;
        }
        if (n)
            std::memcpy(p, buffer_.data() + cursor_, n);
        cursor_ += n;
    }

    void str(std::string& s) {
        if (saving()) {
            std::uint64_t n = s.size();
            raw(&n, sizeof n);
            if (n)
                raw(const_cast<char*>(s.data()), n);
            return;
        }
        std::uint64_t n = 0;
        raw(&n, sizeof n);
        if (failed_)
            return;
        s.resize(n);
        if (n)
            raw(&s[0], n);
    }

    template <class T, std::enable_if_t<std::is_trivially_copyable_v<T>, int> = 0>
    void vec(std::vector<T>& v) {
        if (saving()) {
            std::uint64_t n = v.size();
            raw(&n, sizeof n);
            if (n)
                raw(v.data(), n * sizeof(T));
            return;
        }
        std::uint64_t n = 0;
        raw(&n, sizeof n);
        if (failed_)
            return;
        v.resize(n);
        if (n)
            raw(v.data(), n * sizeof(T));
    }

    // --- file header -------------------------------------------------------------------------
    // magic "DRST", format version, 64-bit payload size, FNV-1a key and FNV-1a payload checksum.
    static constexpr std::uint32_t kVersion = 1;
    static constexpr std::uint64_t kMagic = 0x54535244u;  // 'DRST' little-endian

    bool write_file(const std::string& path, const std::string& key, std::string& err) const;
    bool read_file(const std::string& path, const std::string& key, std::string& err);

private:
    Mode mode_;
    std::vector<std::uint8_t> buffer_;
    std::size_t cursor_ = 0;
    bool failed_ = false;
};

namespace detail {
inline std::uint64_t fnv1a(const void* p, std::size_t n, std::uint64_t h = 1469598103934665603ull) {
    const auto* b = static_cast<const std::uint8_t*>(p);
    for (std::size_t i = 0; i < n; ++i)
        h = (h ^ b[i]) * 1099511628211ull;
    return h;
}
}  // namespace detail

inline bool Archive::write_file(const std::string& path, const std::string& key,
                                std::string& err) const {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        err = "cannot write " + path;
        return false;
    }
    const std::uint64_t size = buffer_.size();
    const std::uint64_t key_hash = detail::fnv1a(key.data(), key.size());
    const std::uint64_t check = detail::fnv1a(buffer_.data(), buffer_.size());
    std::uint32_t version = kVersion;
    std::uint32_t pad = 0;
    std::fwrite(&kMagic, 8, 1, f);
    std::fwrite(&version, 4, 1, f);
    std::fwrite(&pad, 4, 1, f);
    std::fwrite(&size, 8, 1, f);
    std::fwrite(&key_hash, 8, 1, f);
    std::fwrite(&check, 8, 1, f);
    if (size)
        std::fwrite(buffer_.data(), 1, size, f);
    const bool ok = std::ferror(f) == 0;
    std::fclose(f);
    if (!ok) {
        err = "error writing " + path;
        return false;
    }
    return true;
}

inline bool Archive::read_file(const std::string& path, const std::string& key, std::string& err) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        err = "cannot read " + path;
        return false;
    }
    std::uint64_t magic = 0, size = 0, key_hash = 0, check = 0;
    std::uint32_t version = 0, pad = 0;
    if (std::fread(&magic, 8, 1, f) != 1 || std::fread(&version, 4, 1, f) != 1 ||
        std::fread(&pad, 4, 1, f) != 1 || std::fread(&size, 8, 1, f) != 1 ||
        std::fread(&key_hash, 8, 1, f) != 1 || std::fread(&check, 8, 1, f) != 1) {
        std::fclose(f);
        err = path + " is not a state file";
        return false;
    }
    if (magic != kMagic) {
        std::fclose(f);
        err = path + " is not a state file";
        return false;
    }
    if (version != kVersion) {
        std::fclose(f);
        err = "state file format " + std::to_string(version) + " is not " +
              std::to_string(kVersion);
        return false;
    }
    if (key_hash != detail::fnv1a(key.data(), key.size())) {
        std::fclose(f);
        err = "state file was taken from a different build (key mismatch)";
        return false;
    }
    buffer_.resize(size);
    const bool got = size == 0 || std::fread(buffer_.data(), 1, size, f) == size;
    std::fclose(f);
    if (!got) {
        err = path + " is truncated";
        return false;
    }
    if (detail::fnv1a(buffer_.data(), buffer_.size()) != check) {
        err = path + " failed its checksum";
        return false;
    }
    cursor_ = 0;
    return true;
}

}  // namespace dream::state
