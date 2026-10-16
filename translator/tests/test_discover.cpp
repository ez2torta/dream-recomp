// Function discovery: a pointer target whose body ends in BRAF is a complete function.
//
// Capcom vs. SNK reaches its character handlers through a table of 99 code pointers at
// 0x0C1CD068, and each handler ends `mova table,r0 / mov.w @(r0,rN),r0 / braf r0` -- the
// jump-table dispatch idiom -- with its literal pool right behind the jump, where the words
// decode as nothing. While BRAF was missing from the terminator set, plausible_entry() walked on
// past the braf into that pool, met an undefined word and threw the candidate away: the four
// handlers no other code refers to (0x0C0A9508, 0x0C0BA4B0, 0x0C0C8AAC, 0x0C0CE778) were never
// translated, and a release run (DEV=OFF) died on the first one it entered. BRAF moves control
// with no fall-through and no return, so it ends the walk exactly as BRA does.

#include <cstdint>
#include <string>
#include <vector>

#include "dream/translator/analysis/discover.h"

#include "doctest.h"

using dream::translator::DiscoverOptions;
using dream::translator::Image;
using dream::translator::discover;

namespace {

// A 0x20-byte image: an entry point that returns, a data word that points at the handler, and
// the handler itself, which nothing but that word refers to.
Image image_with_braf_handler(std::uint32_t base) {
    Image img;
    img.base = base;
    img.bytes.assign(0x20, 0);
    const auto w16 = [&](std::size_t off, std::uint16_t v) {
        img.bytes[off] = static_cast<std::uint8_t>(v & 0xff);
        img.bytes[off + 1] = static_cast<std::uint8_t>(v >> 8);
    };
    const auto w32 = [&](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i)
            img.bytes[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
    };
    // 0x00: the entry point the caller seeds: nop; rts; nop (the delay slot), then padding.
    w16(0x00, 0x0009);  // nop
    w16(0x02, 0x000b);  // rts
    w16(0x04, 0x0009);  // nop (delay slot)
    w16(0x06, 0x0009);  // nop
    // 0x08: data, not code -- the only reference to the handler.
    w32(0x08, base + 0x10);
    w16(0x0c, 0x0009);  // nop
    // 0x10: the handler, shaped like the real ones: mova; mov.w @(r0,r1),r0; braf r0; nop, and
    // then a word that decodes as nothing, the way a literal pool follows the jump.
    w16(0x10, 0xc701);  // mova @(disp,pc),r0
    w16(0x12, 0x001d);  // mov.w @(r0,r1),r0
    w16(0x14, 0x0023);  // braf r0
    w16(0x16, 0x0009);  // nop (delay slot)
    w16(0x18, 0x01f1);  // undefined
    return img;
}

}  // namespace

TEST_CASE("discovery follows a pointer to a handler that ends in BRAF") {
    const std::uint32_t base = 0x0c010000;
    const Image img = image_with_braf_handler(base);
    DiscoverOptions opt;
    opt.seeds.push_back(base);

    const auto r = discover(img, opt);

    bool found = false;
    for (const auto& f : r.functions)
        if (f.entry == base + 0x10) {
            found = true;
            CHECK(f.origin == "pointer");
        }
    CHECK(found);
}
