/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC-V
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include <M5Utility.hpp>
#include "nfc/v/nfcv.hpp"
#include "nfc/manufacturer_id.hpp"
#include <cstring>
#include <vector>

using namespace m5::nfc;
using namespace m5::nfc::v;

namespace {

struct BitWriter {
    std::vector<uint8_t> bytes{};
    uint32_t bits{};

    void push_bit(const bool bit)
    {
        if ((bits % 8u) == 0u) {
            bytes.push_back(0);
        }
        if (bit) {
            bytes.back() = static_cast<uint8_t>(bytes.back() | (1u << (bits % 8u)));
        }
        ++bits;
    }

    void push_bits_lsb(const uint32_t value, const uint32_t count)
    {
        for (uint32_t i = 0; i < count; ++i) {
            push_bit((value >> i) & 0x01u);
        }
    }

    void align_byte()
    {
        while ((bits % 8u) != 0u) {
            push_bit(false);
        }
    }
};

std::vector<uint8_t> make_payload_with_crc(const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> out{payload};
    m5::utility::CRC16 crc16(0xFFFF, 0x1021, true, true, 0xFFFF);
    const uint16_t crc = crc16.range(out.data(), out.size());
    out.push_back(static_cast<uint8_t>(crc & 0xFFu));
    out.push_back(static_cast<uint8_t>((crc >> 8) & 0xFFu));
    return out;
}

std::vector<uint8_t> make_vicc_frame(const std::vector<uint8_t>& payload_with_crc)
{
    BitWriter bw{};

    // SOF: low 5 bits must be 0x17 (LSB-first).
    bw.push_bits_lsb(0x17u, 5u);

    for (auto byte : payload_with_crc) {
        for (uint8_t bit = 0; bit < 8; ++bit) {
            const bool payload_bit = (byte >> bit) & 0x01u;
            if (payload_bit) {
                // Manchester 10
                bw.push_bit(false);
                bw.push_bit(true);
            } else {
                // Manchester 01
                bw.push_bit(true);
                bw.push_bit(false);
            }
        }
    }

    // Force EOF pattern at the byte boundary the decoder checks.
    const uint32_t payload_bits = static_cast<uint32_t>(payload_with_crc.size()) * 8u;
    const uint32_t mp_end       = 5u + payload_bits * 2u;
    const uint32_t byte_pos     = mp_end / 8u;
    if (bw.bytes.size() <= byte_pos + 1u) {
        bw.bytes.resize(byte_pos + 2u, 0);
        bw.bits = static_cast<uint32_t>(bw.bytes.size()) * 8u;
    }
    bw.bytes[byte_pos]     = static_cast<uint8_t>((bw.bytes[byte_pos] & 0x1Fu) | 0xA0u);
    bw.bytes[byte_pos + 1] = 0x03u;

    return bw.bytes;
}

}  // namespace

TEST(NFC_V, ForumTag)
{
    EXPECT_EQ(get_nfc_forum_tag_type(Type::Unknown), NFCForumTag::None);
    EXPECT_EQ(get_nfc_forum_tag_type(Type::NXP_ICODE_SLI), NFCForumTag::Type5);
}

TEST(NFC_V, PICCHelpers)
{
    PICC picc{};
    std::memset(picc.uid, 0, sizeof(picc.uid));
    picc.uid[0]     = 0xE0;
    picc.uid[1]     = 0x04;
    picc.uid[2]     = 0x01;
    picc.block_size = 4;
    picc.blocks     = 16;
    picc.icRef      = 0x23;
    picc.type       = Type::NXP_ICODE_SLI;

    EXPECT_TRUE(picc.valid());
    EXPECT_EQ(picc.manufacturerCode(), 0x04);
    EXPECT_EQ(picc.icIdentifier(), 0x01);
    EXPECT_EQ(picc.icReference(), 0x23);
    EXPECT_EQ(picc.totalSize(), 64);
    EXPECT_EQ(picc.userAreaSize(), 64);
    EXPECT_EQ(picc.firstUserBlock(), 0);
    EXPECT_EQ(picc.lastUserBlock(), 15);
    EXPECT_EQ(picc.uidAsString(), std::string("E004010000000000"));
    EXPECT_EQ(picc.typeAsString(), std::string("ICODE SLI"));
    EXPECT_EQ(picc.nfcForumTagType(), NFCForumTag::Type5);

    PICC picc2 = picc;
    EXPECT_TRUE(picc == picc2);
    picc2.uid[7] = 0xAA;
    EXPECT_TRUE(picc != picc2);

    PICC invalid{};
    invalid.uid[0] = 0x00;
    EXPECT_FALSE(invalid.valid());
    EXPECT_EQ(invalid.manufacturerCode(), 0xFF);
    EXPECT_EQ(invalid.icIdentifier(), 0x00);
    EXPECT_EQ(invalid.icReference(), 0xFF);
    EXPECT_EQ(invalid.firstUserBlock(), 0xFFFF);
    EXPECT_EQ(invalid.lastUserBlock(), 0xFFFF);
}

TEST(NFC_V, IdentifyType)
{
    PICC picc{};
    picc.uid[0]     = 0xE0;
    picc.block_size = 4;
    picc.blocks     = 1;

    // Unknown (invalid manufacturer or IC identifier)
    picc.uid[1] = 0xFF;
    picc.uid[2] = 0x01;
    picc.icRef  = 0x00;
    EXPECT_EQ(identify_type(picc), Type::Unknown);

    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::NXP);
    picc.uid[2] = 0xFF;
    EXPECT_EQ(identify_type(picc), Type::Unknown);

    // NXP
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::NXP);
    picc.uid[2] = 0x01;
    picc.uid[3] = static_cast<uint8_t>(0u << 3);
    EXPECT_EQ(identify_type(picc), Type::NXP_ICODE_SLI);
    picc.uid[3] = static_cast<uint8_t>(2u << 3);
    EXPECT_EQ(identify_type(picc), Type::NXP_ICODE_SLIX);
    picc.uid[3] = static_cast<uint8_t>(1u << 3);
    EXPECT_EQ(identify_type(picc), Type::NXP_ICODE_SLIX_2);
    picc.uid[2] = 0x02;
    EXPECT_EQ(identify_type(picc), Type::Unclassified);

    // TI
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::TexasInstruments);
    picc.uid[2] = 0x80;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_2048);
    picc.uid[2] = 0x00;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_HF_I_Plus);
    picc.uid[2] = 0xC0;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_HF_I);
    picc.uid[2] = 0xC4;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_HF_I_Pro);
    picc.uid[2] = 0x10;
    EXPECT_EQ(identify_type(picc), Type::TI);

    // ST
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::STMicroelectronics);
    picc.icRef  = 0x23;
    EXPECT_EQ(identify_type(picc), Type::ST_ST25V);
    picc.icRef = 0x24;
    EXPECT_EQ(identify_type(picc), Type::ST_ST25DV);
    picc.icRef = 0x26;
    EXPECT_EQ(identify_type(picc), Type::ST_ST25DV);
    picc.icRef = 0x02;
    EXPECT_EQ(identify_type(picc), Type::ST_LRI);
    picc.icRef = 0x01;
    EXPECT_EQ(identify_type(picc), Type::ST);

    // Fujitsu
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::Fujitsu);
    EXPECT_EQ(identify_type(picc), Type::Fujitsu);

    // Unclassified manufacturer
    picc.uid[1] = 0x99;
    picc.uid[2] = 0x01;
    EXPECT_EQ(identify_type(picc), Type::Unclassified);
}

TEST(NFC_V, EncodeVCD)
{
    std::vector<uint8_t> out{};
    const uint8_t payload[2] = {0x01, 0x02};

    // Null buffer with zero length (EOF only)
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf4, nullptr, 0, true, true), 1u);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], 0x04);

    // Invalid argument combinations
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf4, nullptr, 1, true, true), 0u);
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf4, payload, 0, true, true), 0u);

    // With CRC
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf4, payload, 2, true, true), 18u);
    EXPECT_EQ(out.front(), 0x21);
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf256, payload, 2, true, true), 258u);
    EXPECT_EQ(out.front(), 0x81);

    // Without CRC
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf4, payload, 2, true, false), 10u);
    EXPECT_EQ(encode_VCD(out, ModulationMode::OneOf256, payload, 2, true, false), 130u);
}

TEST(NFC_V, DecodeVICC)
{
    std::vector<uint8_t> out{};

    // Invalid argument
    EXPECT_FALSE(decode_VICC(out, nullptr, 1));
    const uint8_t buf[1] = {0x00};
    EXPECT_FALSE(decode_VICC(out, buf, 0));

    // Invalid SOF
    const uint8_t bad_sof[2] = {0x00, 0x00};
    EXPECT_FALSE(decode_VICC(out, bad_sof, 2));

    // Valid frame
    const std::vector<uint8_t> payload = {0xA5};
    const auto payload_with_crc        = make_payload_with_crc(payload);
    const auto frame                   = make_vicc_frame(payload_with_crc);

    EXPECT_TRUE(decode_VICC(out, frame.data(), frame.size()));
    EXPECT_EQ(out, payload_with_crc);
}

TEST(NFC_V, IdentifyTypeExtended)
{
    PICC picc{};
    EXPECT_FALSE(picc.valid());
    EXPECT_EQ(picc.manufacturerCode(), 0xFF);
    EXPECT_EQ(picc.icIdentifier(), 0x00);
    EXPECT_EQ(picc.icReference(), 0xFF);
    EXPECT_EQ(picc.firstUserBlock(), 0xFFFF);
    EXPECT_EQ(picc.lastUserBlock(), 0xFFFF);
    EXPECT_EQ(picc.userAreaSize(), 0u);
    EXPECT_EQ(picc.nfcForumTagType(), NFCForumTag::None);

    picc.uid[0]     = 0xE0;
    picc.uid[1]     = m5::stl::to_underlying(ManufacturerId::NXP);
    picc.uid[2]     = 0x01;
    picc.uid[3]     = 0x00;  // type indicator bits = 0
    picc.icRef      = 0x23;
    picc.block_size = 4;
    picc.blocks     = 16;
    picc.type       = identify_type(picc);

    EXPECT_TRUE(picc.valid());
    EXPECT_EQ(picc.manufacturerCode(), m5::stl::to_underlying(ManufacturerId::NXP));
    EXPECT_EQ(picc.icIdentifier(), 0x01);
    EXPECT_EQ(picc.icReference(), 0x23);
    EXPECT_EQ(picc.totalSize(), 64);
    EXPECT_EQ(picc.firstUserBlock(), 0u);
    EXPECT_EQ(picc.lastUserBlock(), 15u);
    EXPECT_EQ(picc.nfcForumTagType(), NFCForumTag::Type5);
    EXPECT_EQ(picc.type, Type::NXP_ICODE_SLI);
    EXPECT_FALSE(picc.uidAsString().empty());

    // NXP SLIX / SLIX2
    picc.uid[3] = 0x10;  // type indicator bits = 2
    EXPECT_EQ(identify_type(picc), Type::NXP_ICODE_SLIX);
    picc.uid[3] = 0x08;  // type indicator bits = 1
    EXPECT_EQ(identify_type(picc), Type::NXP_ICODE_SLIX_2);

    // TI
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::TexasInstruments);
    picc.uid[2] = 0x80;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_2048);
    picc.uid[2] = 0xC0;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_HF_I);
    picc.uid[2] = 0xC4;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_HF_I_Pro);
    picc.uid[2] = 0x01;
    EXPECT_EQ(identify_type(picc), Type::TI_TAGIT_HF_I_Plus);

    // ST
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::STMicroelectronics);
    picc.icRef  = 0x23;
    EXPECT_EQ(identify_type(picc), Type::ST_ST25V);
    picc.icRef = 0x24;
    EXPECT_EQ(identify_type(picc), Type::ST_ST25DV);
    picc.icRef = 0x02;
    EXPECT_EQ(identify_type(picc), Type::ST_LRI);

    // Fujitsu
    picc.uid[1] = m5::stl::to_underlying(ManufacturerId::Fujitsu);
    EXPECT_EQ(identify_type(picc), Type::Fujitsu);

    // Unknown
    picc.uid[1] = 0xFF;
    EXPECT_EQ(identify_type(picc), Type::Unknown);
    picc.uid[1] = 0x10;
    picc.uid[2] = 0xFF;
    EXPECT_EQ(identify_type(picc), Type::Unknown);
}
