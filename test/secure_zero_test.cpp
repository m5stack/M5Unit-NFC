/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for secure_zero
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/crypto/secure_zero.hpp"
#include <cstring>

using namespace m5::nfc::crypto;

TEST(SecureZero, Basic)
{
    uint8_t buf[16]{};
    std::memset(buf, 0xAA, sizeof(buf));
    secure_zero(buf, sizeof(buf));
    for (auto b : buf) {
        EXPECT_EQ(b, 0x00);
    }
}

TEST(SecureZero, NullAndZero)
{
    secure_zero(nullptr, 0);
    uint8_t buf[4]{0x11, 0x22, 0x33, 0x44};
    secure_zero(buf, 0);
    EXPECT_EQ(buf[0], 0x11);
}
