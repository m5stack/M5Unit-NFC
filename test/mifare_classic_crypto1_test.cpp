/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for MIFARE Classic Crypto1
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include <M5Utility.hpp>
#include "nfc/crypto/mifare_classic_crypto1.hpp"

using namespace m5::nfc::a::mifare::classic;

namespace {

uint8_t even_parity_bit(uint8_t v)
{
    uint8_t ones{};
    for (uint8_t i = 0; i < 8; ++i) {
        ones += (v >> i) & 0x01u;
    }
    return (ones % 2 == 0) ? 1u : 0u;
}

uint32_t array_to32_be(const uint8_t a[4])
{
    uint32_t v{};
    v |= static_cast<uint32_t>(a[0]) << 24;
    v |= static_cast<uint32_t>(a[1]) << 16;
    v |= static_cast<uint32_t>(a[2]) << 8;
    v |= static_cast<uint32_t>(a[3]) << 0;
    return v;
}

uint32_t suc2_from_nt(uint32_t nt)
{
    m5::utility::FibonacciLFSR_Right<32, 16, 14, 13, 11> tmp(nt);
    tmp.next32();
    tmp.next32();
    return tmp.next32();
}

}  // namespace

TEST(Crypto1, OddParity8)
{
    for (uint16_t i = 0; i < 256; ++i) {
        uint8_t v = static_cast<uint8_t>(i);
        EXPECT_EQ(Crypto1::oddparity8(v), even_parity_bit(v));
    }
}

TEST(Crypto1, InjectConsistency)
{
    constexpr uint64_t key = 0xA0A1A2A3A4A5ULL;
    constexpr uint32_t uid = 0x11223344u;
    constexpr uint32_t nt  = 0x55667788u;

    Crypto1 c1(key);
    Crypto1 c2(key);

    const uint32_t a = c1.inject(uid, nt);
    const uint32_t b = c2.step32(uid ^ nt);
    EXPECT_EQ(a, b);
}

TEST(Crypto1, EncryptParityBoundaries)
{
    Crypto1 c(0x010203040506ULL);

    uint8_t out[8]{};
    uint8_t in[8]{0x00, 0xFF, 0x55, 0xAA, 0x11, 0x22, 0x33, 0x44};

    // in_len = 0 -> parity 0
    EXPECT_EQ(c.encrypt(out, in, 0), 0u);

    // in_len = 4 -> parity only lower 4 bits
    c.init(0x010203040506ULL);
    uint32_t parity = c.encrypt(out, in, 4);
    EXPECT_EQ(parity & ~0x0Fu, 0u);
}

TEST(Crypto1, ProxmarkVector)
{
    // Proxmark3 forum vector (test2.c style)
    // uid=0x9c599b32, nt=0x82a4166c, nr_enc=0xa1e458ce, reader_response=0x6eea41e0
    // ks2=0xe38f32ab, ks3=0xc6ef8f19, key=ffffffffffff
    constexpr uint64_t key = 0xFFFFFFFFFFFFULL;
    const uint8_t uid_b[4] = {0x9C, 0x59, 0x9B, 0x32};
    const uint8_t nt_b[4]  = {0x82, 0xA4, 0x16, 0x6C};
    const uint8_t nr_b[4]  = {0xA1, 0xE4, 0x58, 0xCE};
    const uint8_t rr_b[4]  = {0x6E, 0xEA, 0x41, 0xE0};

    const uint32_t uid    = array_to32_be(uid_b);
    const uint32_t nt     = array_to32_be(nt_b);
    const uint32_t nr_enc = array_to32_be(nr_b);
    const uint32_t ar_enc = array_to32_be(rr_b);

    Crypto1 c1(key);
    c1.inject(uid, nt);
    const uint32_t ks1 = c1.step32(nr_enc, true);
    const uint32_t nr  = nr_enc ^ ks1;

    const uint32_t ar = suc2_from_nt(m5::stl::byteswap(nt));

    Crypto1 c2(key);
    c2.inject(uid, nt);
    uint8_t ab[8]{};
    c2.encrypt(ab, nr, ar);

    EXPECT_TRUE(std::memcmp(ab, nr_b, 4) == 0);
    EXPECT_TRUE(std::memcmp(ab + 4, rr_b, 4) == 0);
}
