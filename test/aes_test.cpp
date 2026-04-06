/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for AES/CMAC
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/crypto/aes.hpp"
#include <cstring>

using namespace m5::nfc::crypto;

namespace {

void hex_to_bytes(const char* hex, uint8_t* out, const size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        char buf[3] = {hex[i * 2], hex[i * 2 + 1], 0};
        out[i]      = static_cast<uint8_t>(std::strtoul(buf, nullptr, 16));
    }
}

}  // namespace

TEST(AES, ECBVector)
{
    uint8_t key[16]{};
    uint8_t in[16]{};
    uint8_t out[16]{};
    uint8_t expected[16]{};

    hex_to_bytes("000102030405060708090A0B0C0D0E0F", key, 16);
    hex_to_bytes("00112233445566778899AABBCCDDEEFF", in, 16);
    hex_to_bytes("69C4E0D86A7B0430D8CDB78070B4C55A", expected, 16);

    ASSERT_TRUE(aes_ecb_encrypt(out, key, in));
    EXPECT_TRUE(std::memcmp(out, expected, 16) == 0);
}

TEST(AES, CBCVector)
{
    uint8_t key[16]{};
    uint8_t iv[16]{};
    uint8_t in[16]{};
    uint8_t out[16]{};
    uint8_t back[16]{};
    uint8_t expected[16]{};

    hex_to_bytes("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
    hex_to_bytes("000102030405060708090A0B0C0D0E0F", iv, 16);
    hex_to_bytes("6BC1BEE22E409F96E93D7E117393172A", in, 16);
    hex_to_bytes("7649ABAC8119B246CEE98E9B12E9197D", expected, 16);

    ASSERT_TRUE(aes_cbc_crypt(out, key, iv, in, sizeof(in), true));
    EXPECT_TRUE(std::memcmp(out, expected, 16) == 0);

    // Decrypt back
    ASSERT_TRUE(aes_cbc_crypt(back, key, iv, out, sizeof(out), false));
    EXPECT_TRUE(std::memcmp(back, in, 16) == 0);
}

TEST(AES, CMACVectors)
{
    uint8_t key[16]{};
    uint8_t out[16]{};
    uint8_t expected[16]{};

    hex_to_bytes("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);

    // RFC 4493 vectors
    ASSERT_TRUE(cmac_aes_128(out, key, nullptr, 0));
    hex_to_bytes("BB1D6929E95937287FA37D129B756746", expected, 16);
    EXPECT_TRUE(std::memcmp(out, expected, 16) == 0);

    uint8_t msg1[16]{};
    hex_to_bytes("6BC1BEE22E409F96E93D7E117393172A", msg1, 16);
    ASSERT_TRUE(cmac_aes_128(out, key, msg1, sizeof(msg1)));
    hex_to_bytes("070A16B46B4D4144F79BDD9DD04A287C", expected, 16);
    EXPECT_TRUE(std::memcmp(out, expected, 16) == 0);

    uint8_t msg2[40]{};
    hex_to_bytes("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411", msg2, 40);
    ASSERT_TRUE(cmac_aes_128(out, key, msg2, sizeof(msg2)));
    hex_to_bytes("DFA66747DE9AE63030CA32611497C827", expected, 16);
    EXPECT_TRUE(std::memcmp(out, expected, 16) == 0);

    uint8_t msg3[64]{};
    hex_to_bytes(
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
        "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        msg3, 64);
    ASSERT_TRUE(cmac_aes_128(out, key, msg3, sizeof(msg3)));
    hex_to_bytes("51F0BEBF7E3B9D92FC49741779363CFE", expected, 16);
    EXPECT_TRUE(std::memcmp(out, expected, 16) == 0);
}

TEST(AES, InvalidArgs)
{
    uint8_t out[16]{};
    uint8_t key[16]{};
    uint8_t in[16]{};
    uint8_t iv[16]{};

    EXPECT_FALSE(aes_ecb_encrypt(nullptr, key, in));
    EXPECT_FALSE(aes_ecb_encrypt(out, nullptr, in));
    EXPECT_FALSE(aes_ecb_encrypt(out, key, nullptr));

    EXPECT_FALSE(aes_cbc_crypt(nullptr, key, iv, in, sizeof(in), true));
    EXPECT_FALSE(aes_cbc_crypt(out, nullptr, iv, in, sizeof(in), true));
    EXPECT_FALSE(aes_cbc_crypt(out, key, nullptr, in, sizeof(in), true));
    EXPECT_FALSE(aes_cbc_crypt(out, key, iv, nullptr, sizeof(in), true));

    EXPECT_FALSE(cmac_subkeys(nullptr, out, key));
    EXPECT_FALSE(cmac_subkeys(out, nullptr, key));
    EXPECT_FALSE(cmac_subkeys(out, out, nullptr));

    EXPECT_FALSE(cmac_aes_128(nullptr, key, in, sizeof(in)));
    EXPECT_FALSE(cmac_aes_128(out, nullptr, in, sizeof(in)));
    EXPECT_FALSE(cmac_aes_128(out, key, nullptr, sizeof(in)));
}
