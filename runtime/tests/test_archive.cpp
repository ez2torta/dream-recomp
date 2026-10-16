// The savestate archive, read from the wrong side: a file that is not from this build.
//
// A state pins the executable -- the same devices in the same order, each writing the same fields.
// When it does not match, the stream desynchronises and the next count read is whatever bytes
// happen to be there. Resizing a vector to that count threw `std::length_error` from inside a
// device, which escaped the run loop and aborted the process with a core dump
// (2026-10-16, `Maple::Bus::serialize`). A stale file should cost an error message, not a crash.
//
// Three rules keep it that way, and each has a case below:
//   1. a count is only believed when the payload can hold that many bytes (`Archive::reserve`);
//   2. a load must consume the whole payload, which the launcher checks on `cursor()`;
//   3. a truncated or tampered file fails the magic, the key or the checksum before any of it.
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "dream/runtime/maple/maple.h"
#include "dream/runtime/state/archive.h"
#include "dream/runtime/system.h"

#include "doctest.h"

using dream::state::Archive;

namespace {

// One directory per call, numbered rather than named after the process: getpid() is not portable
// and these tests run on every CI host.
std::filesystem::path temp_file(const char* name) {
    static int n = 0;
    const auto d =
        std::filesystem::temp_directory_path() / ("dream-archive-" + std::to_string(n++));
    std::error_code ec;
    std::filesystem::remove_all(d, ec);
    std::filesystem::create_directories(d, ec);
    return d / name;
}

// A payload carrying `junk` before `body`. Writing it is how this test speaks for a build whose
// device list or field order differs from the one that wrote the state.
bool write_shifted(const std::filesystem::path& path, const std::vector<std::uint8_t>& junk,
                   const std::vector<std::uint8_t>& body) {
    Archive out(Archive::Mode::Save);
    out.raw(const_cast<std::uint8_t*>(junk.data()), junk.size());
    out.raw(const_cast<std::uint8_t*>(body.data()), body.size());
    std::string err;
    return out.write_file(path.string(), "key", err);
}

}  // namespace

TEST_CASE("archive: a round trip reads back what was written, and consumes all of it") {
    const auto path = temp_file("round.state");
    std::vector<std::uint32_t> words{1, 2, 3, 0xDEADBEEFu};
    std::string text = "training";
    std::uint64_t count = 9;
    std::string err;
    {
        Archive out(Archive::Mode::Save);
        out.vec(words);
        out.str(text);
        out.pod(count);
        REQUIRE(out.write_file(path.string(), "key", err));
    }
    Archive in(Archive::Mode::Load);
    REQUIRE(in.read_file(path.string(), "key", err));
    std::vector<std::uint32_t> read_words;
    std::string read_text;
    std::uint64_t read_count = 0;
    in.vec(read_words);
    in.str(read_text);
    in.pod(read_count);
    CHECK_FALSE(in.failed());
    CHECK(read_words == words);
    CHECK(read_text == text);
    CHECK(read_count == count);
    CHECK(in.cursor() == in.buffer().size());
}

TEST_CASE("archive: a count the payload cannot hold is refused, not resized") {
    // The smallest version of a stale state: a writer promised 16 Mi elements, and the reader's
    // build reads that count against bytes that belong to something else.
    const auto path = temp_file("garbage.state");
    std::string err;
    {
        Archive out(Archive::Mode::Save);
        std::uint64_t promised = 16u * 1024u * 1024u;
        out.raw(&promised, sizeof promised);
        std::uint32_t one = 1;
        out.raw(&one, sizeof one);
        REQUIRE(out.write_file(path.string(), "key", err));
    }
    Archive in(Archive::Mode::Load);
    REQUIRE(in.read_file(path.string(), "key", err));
    std::vector<std::uint32_t> v;
    CHECK_NOTHROW(in.vec(v));  // before: std::length_error, then SIGABRT
    CHECK(in.failed());
    CHECK(v.empty());
}

TEST_CASE("archive: a string count the payload cannot hold is refused, not resized") {
    const auto path = temp_file("garbage-string.state");
    std::string err;
    {
        Archive out(Archive::Mode::Save);
        std::uint64_t promised = ~std::uint64_t{0};  // worst case: would throw length_error
        out.raw(&promised, sizeof promised);
        std::uint8_t one = 1;
        out.raw(&one, sizeof one);
        REQUIRE(out.write_file(path.string(), "key", err));
    }
    Archive in(Archive::Mode::Load);
    REQUIRE(in.read_file(path.string(), "key", err));
    std::string s = "untouched";
    CHECK_NOTHROW(in.str(s));
    CHECK(in.failed());
    CHECK(s == "untouched");
}

TEST_CASE("archive: a field this build does not know about is detectable as unconsumed bytes") {
    // A field added between the save and the load: the reader stops before the end. This is the
    // second rule, and it is what the launcher refuses a state on, because a resume that read the
    // wrong number of bytes has read the wrong values.
    const auto path = temp_file("trailing.state");
    std::string err;
    {
        Archive out(Archive::Mode::Save);
        std::uint32_t known = 7, added = 9;
        out.pod(known);
        out.pod(added);
        REQUIRE(out.write_file(path.string(), "key", err));
    }
    Archive in(Archive::Mode::Load);
    REQUIRE(in.read_file(path.string(), "key", err));
    std::uint32_t known = 0;
    in.pod(known);
    CHECK_FALSE(in.failed());
    CHECK(known == 7);
    CHECK(in.cursor() != in.buffer().size());
}

TEST_CASE("maple bus: a shifted stream is refused rather than resized") {
    // The shape of the crash that started this: a bus reading a count that belongs to another
    // field. A real bus is serialized, then read back from a stream one word ahead -- what a field
    // added earlier in the machine does to every device after it.
    dream::System sys;
    dream::maple::Bus bus{sys.sched, sys.holly, sys.memory};
    bus.attach(0, std::make_unique<dream::maple::Controller>());

    Archive saved(Archive::Mode::Save);
    bus.serialize(saved);
    const auto& body = saved.buffer();
    REQUIRE(body.size() > 16);

    const auto path = temp_file("shifted.state");
    std::string err;
    const std::vector<std::uint8_t> junk{0xAA, 0xBB, 0xCC, 0xDD};
    REQUIRE(write_shifted(path, junk, body));

    dream::System other;
    dream::maple::Bus shifted{other.sched, other.holly, other.memory};
    shifted.attach(0, std::make_unique<dream::maple::Controller>());
    Archive in(Archive::Mode::Load);
    REQUIRE(in.read_file(path.string(), "key", err));
    CHECK_NOTHROW(shifted.serialize(in));  // before: aborted from inside the bus
    // Either a count was refused, or the stream ran out short of its end -- the two rules are
    // complementary: `reserve` catches a count that overruns, and the launcher's cursor check
    // catches a stream that stops early. What must not happen is a load that looks clean and is
    // half-applied, which is why the launcher demands every byte.
    const bool caught = in.failed() || in.cursor() != in.buffer().size();
    CHECK(caught);
}

TEST_CASE("archive: a foreign key, a tampered payload and a truncated file are refused") {
    const auto path = temp_file("refused.state");
    std::string err;
    {
        Archive out(Archive::Mode::Save);
        std::uint64_t value = 0x1122334455667788ull;
        out.pod(value);
        REQUIRE(out.write_file(path.string(), "key", err));
    }
    Archive wrong_key(Archive::Mode::Load);
    CHECK_FALSE(wrong_key.read_file(path.string(), "another key", err));
    CHECK(err.find("different build") != std::string::npos);

    // Flip one payload byte in place: the checksum is what notices.
    auto bytes = [&] {
        std::FILE* f = std::fopen(path.string().c_str(), "rb");
        REQUIRE(f);
        std::vector<std::uint8_t> b(64);
        const std::size_t got = std::fread(b.data(), 1, b.size(), f);
        b.resize(got);
        std::fclose(f);
        return b;
    }();
    REQUIRE(bytes.size() > 40);
    const auto write_bytes = [&](const std::vector<std::uint8_t>& b) {
        std::FILE* f = std::fopen(path.string().c_str(), "wb");
        REQUIRE(f);
        std::fwrite(b.data(), 1, b.size(), f);
        std::fclose(f);
    };
    auto tampered = bytes;
    tampered.back() ^= 0xFF;
    write_bytes(tampered);
    Archive bad_sum(Archive::Mode::Load);
    CHECK_FALSE(bad_sum.read_file(path.string(), "key", err));
    CHECK(err.find("checksum") != std::string::npos);

    auto truncated = bytes;
    truncated.resize(truncated.size() - 4);
    write_bytes(truncated);
    Archive short_file(Archive::Mode::Load);
    CHECK_FALSE(short_file.read_file(path.string(), "key", err));
}
