/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file mifare.hpp
  @brief Mifare definitions
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_A_MIFARE_CRYPTO1_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_A_MIFARE_CRYPTO1_HPP

#include <M5Utility.hpp>

namespace m5 {
namespace nfc {
namespace a {
namespace mifare {

using MLFSR48 = m5::utility::FibonacciLFSR_Left<48, 5, 6, 7, 9, 13, 19, 21, 23, 24, 29, 31, 33, 34, 36, 38, 39, 43, 48>;
class MifareCrypto1 : public MLFSR48 {
public:
    MifareCrypto1() noexcept : MLFSR48(0)
    {
    }

    explicit MifareCrypto1(const uint64_t key48) noexcept : MLFSR48(0)
    {
        init(key48);
    }

    void init(const uint64_t key48) noexcept
    {
        _state = state_type_t{};
        // Change the bit order within the byte to LSB first
        for (int i = 0; i < 48; ++i) {
            int byte_index = i >> 3;
            int bit_index  = i & 0x07;
            int reversed   = (byte_index << 3) + (bit_index ^ 7);
            bool bit       = (key48 >> reversed) & 1ULL;
            _state[i]      = bit;
        }
        _count = 0;
    }

    inline uint32_t inject(uint32_t uid, uint32_t Nt, const bool encrypted = false) noexcept
    {
        return step32(uid ^ Nt, encrypted);
    }

    bool step_with(const bool in, const bool enc = false) noexcept
    {
        ++_count;

        bool z = filter();
        (void)step();
        const bool ext = in ^ (enc ? z : 0);
        _state[0]      = _state[0] ^ ext;
        return z;
    }

    uint8_t step8(const uint8_t in, const bool enc = false) noexcept
    {
        uint8_t v{};
        for (uint_fast8_t i = 0; i < 8; ++i) {
            v |= step_with((in >> i) & 1, enc) << i;
        }
        return v;
    }

    uint32_t step32(const uint32_t in, const bool enc = false) noexcept
    {
        uint32_t v{};
        for (uint32_t i = 0; i < 32; ++i) {
            bool t = step_with((in >> (i ^ 24)) & 1u, enc);
            v |= t << (24 ^ i);
        }
        return v;
    }

    static inline uint8_t oddparity8(uint8_t x) noexcept
    {
        return !__builtin_parity(x);
    }

    uint8_t encrypt(uint8_t buf[8], const uint32_t Nr, const uint32_t Ar) noexcept
    {
        uint8_t parity{};
        for (uint_fast8_t i = 0; i < 4; ++i) {
            const uint8_t v = ((Nr >> ((i ^ 0x03) << 3)) & 0xFF);
            buf[i]          = step8(v) ^ v;
            const uint8_t z = filter();
            parity |= static_cast<uint8_t>((z ^ oddparity8(v)) & 0x01) << i;
        }

        for (uint_fast8_t pos = 4; pos < 8; ++pos) {
            const uint8_t i = pos - 4;
            // const uint8_t v = static_cast<uint8_t>(Ar >> (i << 3));
            const uint8_t v  = (Ar >> (i << 3)) & 0xFF;
            const uint8_t ks = step8(0x00);
            buf[pos]         = ks ^ v;
            const uint8_t z  = filter();
            parity |= static_cast<uint8_t>((z ^ oddparity8(v)) & 0x01) << pos;
        }
        return parity;
    }

    uint32_t encrypt(uint8_t* out, const uint8_t* in, const uint8_t in_len /* max 32 */)
    {
        uint32_t parity{};
        for (uint_fast8_t i = 0; i < in_len; ++i) {
            uint8_t ks = step8(0);
            out[i]     = in[i] ^ ks;
            parity |= ((filter() ^ oddparity8(in[i])) & 1) << i;
        }
        return parity;
    }

    inline bool filter() const noexcept
    {
        const state_type_t& s = state();
        const bool b5         = fb(s[6], s[4], s[2], s[0]);
        const bool a4         = fa(s[14], s[12], s[10], s[8]);
        const bool b3         = fb(s[22], s[20], s[18], s[16]);
        const bool b2         = fb(s[30], s[28], s[26], s[24]);
        const bool a1         = fa(s[38], s[36], s[34], s[32]);
        return fc(a1, b2, b3, a4, b5);
    }

    inline static bool fa(bool a, bool b, bool c, bool d) noexcept
    {
        return ((a || b) ^ (a && d)) ^ (c && ((a ^ b) || d));
    }

    inline static bool fb(bool a, bool b, bool c, bool d) noexcept
    {
        return ((a && b) || c) ^ ((a ^ b) && (c || d));
    }

    inline static bool fc(bool a, bool b, bool c, bool d, bool e) noexcept
    {
        return (a || ((b || e) && (d ^ e))) ^ ((a ^ (b && d)) && ((c ^ d) || (b && e)));
    }

    uint32_t _count{};  // for debug
};

}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5

#endif
