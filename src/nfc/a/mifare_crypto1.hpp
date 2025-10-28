#pragma once
#include <M5Utility.hpp>

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

    uint64_t valueLSBFirst() const noexcept
    {
        uint64_t v = 0;
        for (int i = 23; i >= 0; --i) {
            const int j = (i ^ 3);                                              // nibble 反転
            v           = (v << 1) | static_cast<uint64_t>(_state[2 * j]);      // odd列のビット
            v           = (v << 1) | static_cast<uint64_t>(_state[2 * j + 1]);  // even列のビット
        }
        return v;
    }

    void init(const uint64_t key48) noexcept
    {
        _state = state_type_t{};
        // Change the bit order within the byte to LSB first (*1)
        for (int i = 0; i < 48; ++i) {
            int byte_index = i >> 3;
            int bit_index  = i & 0x07;
            int reversed   = (byte_index << 3) + (bit_index ^ 7);
            bool bit       = (key48 >> reversed) & 1ULL;
            _state[i]      = bit;
        }
        _uid   = key48;
        _count = 0;
    }

    inline void inject(uint32_t uid, uint32_t Nt) noexcept
    {
        (void)step32(uid ^ Nt);
    }

    bool step_with(const bool in, const bool enc = false) noexcept
    {
        ++_count;

        bool z = filter();
#if 1
        (void)step();
        const bool ext = in ^ (enc ? z : 0);
        _state[0]      = _state[0] ^ ext;
#else
        static constexpr uint64_t LF_POLY_48 = 0x0000846B50D41170ULL;
        uint8_t fb = __builtin_parityll((value() & LF_POLY_48) ^ (in & 1) ^ (enc ? (z & 1) : 0));
        _state <<= 1;
        _state.set(0, fb);
#endif
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
        uint8_t par{};
        for (uint_fast8_t i = 0; i < 4; ++i) {
            uint8_t v = ((Nr >> ((i ^ 0x03) << 3)) & 0xFF);
            buf[i]    = step8(v) ^ v;

            const uint8_t z = filter();
            // uint8_t aaa     = (z ^ oddparity8(v)) & 0x01;
            //             M5_LIB_LOGE("pos[%u]: f:%d P:%u", i, z, aaa);

            //            par |= static_cast<uint8_t>((z ^ oddparity8(v)) & 0x01) << (7 - i);
            par |= static_cast<uint8_t>((z ^ oddparity8(v)) & 0x01) << i;
        }
#if 0
        for (uint_fast8_t i = 0; i < 4; ++i) {
            buf[4 + i]      = step8(0) ^ ((Ar >> (i << 3)) & 0xFF);
        }
#else
        for (uint_fast8_t pos = 4; pos < 8; ++pos) {
            const uint8_t i       = pos - 4;
            const uint8_t nt_byte = static_cast<uint8_t>(Ar >> (i << 3));
            const uint8_t ks      = step8(0x00);
            buf[pos]              = ks ^ nt_byte;

            const uint8_t z = filter();
            // uint8_t aaa     = (z ^ oddparity8(nt_byte)) & 0x01;
            //             M5_LIB_LOGE("pos[%u]: f:%d P:%u", pos, z, aaa);
            //            par |= static_cast<uint8_t>((z ^ oddparity8(nt_byte)) & 0x01) << (7 - pos);
            par |= static_cast<uint8_t>((z ^ oddparity8(nt_byte)) & 0x01) << pos;
        }

#endif
        M5_LIB_LOGE("MyPar:%02X", par);
        return par;
    }

#if 0    
    void encrypt(std::vector<uint8_t>& out, const uint8_t* tx, const uint16_t len)
    {
        out.clear();
        out.resize(tx_len + ((tx_len + 7) >> 3));

        for (uint_fast16_t i = 0; i < len; ++i) {
            uint8_t ks = _crypto1.step8(0);
            enc_tx[i]  = tx[i] ^ ks;
            
        }
    }
#endif

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

    /*
       These macros are linearized boolean tables for the output filter functions.
       E.g. fa(0,1,0,1) is (mf2_f4a >> 0x5)&1
     const uint32_t mf2_f4a = 0x9E98;
     const uint32_t mf2_f4b = 0xB48E;
     const uint32_t mf2_f5c = 0xEC57E80A;

const uint32_t i5 = ((mf2_f4b >> i4 (x, 7+d, 9+d,11+d,13+d)) & 1)<<0
59 | ((mf2_f4a >> i4 (x,15+d,17+d,19+d,21+d)) & 1)<<1
60 | ((mf2_f4a >> i4 (x,23+d,25+d,27+d,29+d)) & 1)<<2
61 | ((mf2_f4b >> i4 (x,31+d,33+d,35+d,37+d)) & 1)<<3
62 | ((mf2_f4a >> i4 (x,39+d,41+d,43+d,45+d)) & 1)<<4;
63
64 return (mf2_f5c >> i5) & 1;
    */

    inline static bool fa(bool a, bool b, bool c, bool d) noexcept
    {
        return ((a || b) ^ (a && d)) ^ (c && ((a ^ b) || d));
        // const uint8_t x = a | (b << 1) | (c << 2) | (d << 3);
        const uint8_t x = (a << 3) | (b << 2) | (c << 1) | (d << 0);

        // return (0xf22cu >> x) & 1u;
        return ((0xD9380u >> x) & 16u);
        //        return ((0xB48Eu >> x) & 1u) != 0;
        // return (0x9E98u >> x) & 1u;
    }

    inline static bool fb(bool a, bool b, bool c, bool d) noexcept
    {
        return ((a && b) || c) ^ ((a ^ b) && (c || d));
        // const uint8_t x = a | (b << 1) | (c << 2) | (d << 3);
        const uint8_t x = (a << 3) | (b << 2) | (c << 1) | (d << 0);

        // return ((0xD938u >> x) & 1u) != 0;
        return ((0xf22c0 >> x) & 16u);
        //        return (0x9E98u >> x) & 1u;
        // return (0xB48Eu >> x) & 1u;
    }

    inline static bool fc(bool a, bool b, bool c, bool d, bool e) noexcept
    {
        return (a || ((b || e) && (d ^ e))) ^ ((a ^ (b && d)) && ((c ^ d) || (b && e)));
        // uint8_t x = (unsigned)a << 4 | (unsigned)b << 3 | (unsigned)c << 2 | (unsigned)d << 1 | (unsigned)e;
        //        const uint8_t x = (a << 0) | (b << 1) | (c << 2) | (d << 3) | (e << 4);
        const uint8_t x = (a << 4) | (b << 3) | (c << 2) | (d << 1) | (e << 0);
        return ((0xEC57E80Au >> x) & 1u) != 0;
    }

    //////
    static inline uint32_t pack_even24(const state_type_t& s)
    {
        uint32_t x = 0;
        for (int k = 0; k < 24; ++k) {
            x |= (uint32_t(s[2 * k]) << k);  // 偶数添字から LSB→MSB に詰める
            // 0,2,4....
            // [46][44] .... [2][0]B
        }
        return x;
    }

    static inline bool filter_lut(const state_type_t& s)
    {
        uint32_t x = pack_even24(s);
        uint32_t f[5]{};
        f[0]        = 0xf22c0 >> (x & 0xF) & 16;         // 0xf22c << 4
        f[1]        = 0x6c9c0 >> ((x >> 4) & 0xF) & 8;   // 0xd938 << 3
        f[2]        = 0x3c8b0 >> ((x >> 8) & 0xF) & 4;   // 0xf22c << 2
        f[3]        = 0x1e458 >> ((x >> 12) & 0xF) & 2;  // 0xf22c << 1
        f[4]        = 0x0d938 >> ((x >> 16) & 0xF) & 1;  // 0xd938 << 0
        uint32_t ff = f[0] | f[1] | f[2] | f[3] | f[4];

        M5_LIB_LOGI("%02X:%02X:%02X:%02X:%02X %u:%u:%u:%u:%u", (x & 0x0F), ((x >> 4) & 0xF), ((x >> 8) & 0xF),
                    ((x >> 12) & 0xF), ((x >> 16) & 0xF), (bool)f[0], (bool)f[1], (bool)f[2], (bool)f[3], (bool)f[4]);

        /*
        M5_LOGI("(%x)%u:(%x)%u:(%x)%u:(%x)%u:(%x)%u %x => %u",  //
                (x & 0x0F), f[0],                               //
                ((x >> 4) & 0xF), f[1],                         //
                ((x >> 8) & 0xF), f[2],                         //
                ((x >> 12) & 0xF), f[3],                        //
                ((x >> 16) & 0xF), f[4],                        //
                ff, ((0xEC57E80Au >> ff) & 1u) != 0);
        */
        return ((0xEC57E80Au >> ff) & 1u) != 0;
    }

    uint64_t _uid{};
    uint32_t _count{};  // for debug
};
