/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC-B
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/b/nfcb.hpp"
#include <cstring>

using namespace m5::nfc;
using namespace m5::nfc::b;

namespace {

constexpr uint16_t frame_length_table[9] = {
    16, 24, 32, 40, 48, 64, 96, 128, 256,
};

}  // namespace

TEST(NFC_B, ProtocolHelpers)
{
    uint8_t protocol[3] = {0};

    // Null-safe helpers
    EXPECT_EQ(maximum_frame_length(nullptr), 0u);
    EXPECT_EQ(maximum_frame_length_bits(nullptr), 0x0F);
    EXPECT_FALSE(supports_iso14443_4(nullptr));
    EXPECT_EQ(get_frame_option(nullptr), 0u);
    EXPECT_EQ(get_fwi(nullptr), 0x0F);

    // maximum_frame_length_bits
    protocol[1] = 0x30;
    EXPECT_EQ(maximum_frame_length_bits(protocol), 0x03);

    // supports_iso14443_4
    protocol[1] = 0x01;
    EXPECT_TRUE(supports_iso14443_4(protocol));
    protocol[1] = 0x00;
    EXPECT_FALSE(supports_iso14443_4(protocol));

    // get_frame_option / get_fwi
    protocol[2] = 0xA3;
    EXPECT_EQ(get_frame_option(protocol), 0x03);
    EXPECT_EQ(get_fwi(protocol), 0x0A);

    protocol[2] = 0x00;
    EXPECT_EQ(get_frame_option(protocol), 0x00);
    EXPECT_EQ(get_fwi(protocol), 0x00);

    protocol[2] = 0xFF;
    EXPECT_EQ(get_frame_option(protocol), 0x03);
    EXPECT_EQ(get_fwi(protocol), 0x0F);
}

TEST(NFC_B, MaximumFrameLength)
{
    uint8_t protocol[3] = {0};
    for (uint8_t i = 0; i < 9; ++i) {
        protocol[1] = static_cast<uint8_t>(i << 4);
        EXPECT_EQ(maximum_frame_length(protocol), frame_length_table[i]);
    }

    protocol[1] = 0x00;
    EXPECT_EQ(maximum_frame_length(protocol), 16u);

    protocol[1] = 0x90;
    EXPECT_EQ(maximum_frame_length(protocol), 0u);

    protocol[1] = 0xFF;
    EXPECT_EQ(maximum_frame_length(protocol), 0u);
}

TEST(NFC_B, PICC)
{
    PICC picc{};
    std::memset(picc.atqb, 0, sizeof(picc.atqb));

    // Not ISO14443-4
    picc.protocol[1] = 0x00;
    EXPECT_FALSE(picc.valid());
    EXPECT_FALSE(picc.isISO14443_4());

    // ISO14443-4
    picc.protocol[0] = COMMUNICATION_SPPED_424K_FROM_PICC | COMMUNICATION_SPPED_212K_TO_PICC;
    picc.protocol[1] = 0x11;
    picc.protocol[2] = FRAME_OPTION_NAD | FRAME_OPTION_CID | (0x0A << 4);
    picc.type        = Type::Unclassified;
    picc.cid         = 0x02;
    picc.pupi[0]     = 0xE1;
    picc.pupi[1]     = 0xE2;
    picc.pupi[2]     = 0xE3;
    picc.pupi[3]     = 0xE4;

    EXPECT_TRUE(picc.valid());
    EXPECT_TRUE(picc.isISO14443_4());
    EXPECT_TRUE(picc.supportsNAD());
    EXPECT_TRUE(picc.supportsCID());
    EXPECT_EQ(picc.maximumFrameLengthBits(), 0x01);
    EXPECT_EQ(picc.maximumFrameLength(), 24);
    EXPECT_EQ(picc.communicationSpeed(),
              static_cast<uint8_t>(COMMUNICATION_SPPED_424K_FROM_PICC | COMMUNICATION_SPPED_212K_TO_PICC));
    EXPECT_EQ(picc.fwi(), 0x0A);

    EXPECT_EQ(picc.pupiAsString(), std::string("E1E2E3E4"));
    EXPECT_EQ(picc.typeAsString(), std::string("Unclassified"));

    PICC picc2 = picc;
    EXPECT_TRUE(picc == picc2);
    picc2.atqb[0] = 0xAA;
    EXPECT_TRUE(picc != picc2);

    // Out of range type should map to Unknown
    picc.type = static_cast<Type>(0xFF);
    EXPECT_EQ(picc.typeAsString(), std::string("Unknown"));
}
