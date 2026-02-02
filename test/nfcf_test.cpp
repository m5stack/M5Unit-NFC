/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC-F
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/f/nfcf.hpp"
#include <cstring>

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {

constexpr uint8_t kIdm[FELICA_ID_LENGTH] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
constexpr uint8_t kPmm[FELICA_ID_LENGTH] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};

}  // namespace

TEST(NFC_F, TimeSlot)
{
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot1), 1);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot2), 2);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot4), 4);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot8), 8);
    EXPECT_EQ(timeslot_to_slot(TimeSlot::Slot16), 16);
    EXPECT_EQ(timeslot_to_slot(static_cast<TimeSlot>(0xFF)), 0);
}

TEST(NFC_F, Block)
{
    block_t b{0x0102, 0x03, 0x04};
    EXPECT_TRUE(b.is_3byte());
    EXPECT_FALSE(b.is_2byte());
    EXPECT_EQ(b.access_mode(), 0x03);
    EXPECT_EQ(b.order(), 0x04);
    EXPECT_EQ(b.block(), 0x0102);

    uint8_t buf[3] = {0};
    auto len       = b.store(buf);
    EXPECT_EQ(len, 3u);
    EXPECT_EQ(buf[0], b.header);
    EXPECT_EQ(buf[1], 0x02);
    EXPECT_EQ(buf[2], 0x01);

    auto b2 = block_t::from(buf);
    EXPECT_TRUE(b2.is_3byte());
    EXPECT_EQ(b2.block(), 0x0102);
    EXPECT_EQ(b2.access_mode(), 0x03);
    EXPECT_EQ(b2.order(), 0x04);

    b2.block(0x00FE);
    EXPECT_TRUE(b2.is_2byte());
    EXPECT_EQ(b2.block(), 0x00FE);

    b2.access_mode(0x07);
    b2.order(0x0F);
    EXPECT_EQ(b2.access_mode(), 0x07);
    EXPECT_EQ(b2.order(), 0x0F);
}

TEST(NFC_F, UserArea)
{
    EXPECT_EQ(get_nfc_forum_tag_type(Type::Unknown), NFCForumTag::None);
    EXPECT_EQ(get_nfc_forum_tag_type(Type::FeliCaLiteS), NFCForumTag::Type3);

    EXPECT_EQ(get_number_of_user_blocks(Type::Unknown), 0);
    EXPECT_EQ(get_number_of_user_blocks(Type::FeliCaLite), 14);
    EXPECT_EQ(get_number_of_user_blocks(Type::FeliCaLiteS), 14);

    EXPECT_EQ(get_first_user_block(Type::FeliCaLite), 0);
    EXPECT_EQ(get_last_user_block(Type::FeliCaLite), 0x0D);

    EXPECT_TRUE(is_user_block(Type::FeliCaLite, 0));
    EXPECT_TRUE(is_user_block(Type::FeliCaLite, 0x0D));
    EXPECT_FALSE(is_user_block(Type::FeliCaLite, 0x0E));

    EXPECT_EQ(get_maxumum_read_blocks(Type::FeliCaStandard), 8u);
    EXPECT_EQ(get_maxumum_read_blocks(Type::FeliCaLite), 4u);
    EXPECT_EQ(get_maxumum_write_blocks(Type::FeliCaLiteS), 1u);
}

TEST(NFC_F, PICC)
{
    PICC picc{};
    EXPECT_FALSE(picc.valid());
    EXPECT_FALSE(picc.validEmulation());
    EXPECT_EQ(picc.firstUserBlock(), 0xFFFF);
    EXPECT_EQ(picc.lastUserBlock(), 0xFFFF);
    EXPECT_EQ(picc.userAreaSize(), 0u);
    EXPECT_EQ(picc.nfcForumTagType(), NFCForumTag::None);

    std::memcpy(picc.idm, kIdm, sizeof(kIdm));
    std::memcpy(picc.pmm, kPmm, sizeof(kPmm));
    picc.type         = Type::FeliCaLiteS;
    picc.format       = format_lite;
    picc.emulation_sc = system_code_lite;

    EXPECT_TRUE(picc.valid());
    EXPECT_TRUE(picc.validEmulation());
    EXPECT_EQ(picc.userAreaSize(), 16u * 14u);
    EXPECT_EQ(picc.firstUserBlock(), 0u);
    EXPECT_EQ(picc.lastUserBlock(), 0x0Du);
    EXPECT_TRUE(picc.isUserBlock(block_t{0x0D}));
    EXPECT_FALSE(picc.isUserBlock(block_t{0x0E}));

    EXPECT_EQ(picc.idmAsString(), std::string("0123456789ABCDEF"));
    EXPECT_EQ(picc.pmmAsString(), std::string("1032547698BADCFE"));
    EXPECT_EQ(picc.typeAsString(), std::string("FeliCa Lite-S"));

    PICC picc2 = picc;
    EXPECT_TRUE(picc == picc2);
    picc2.pmm[0] ^= 0x01;
    EXPECT_TRUE(picc != picc2);

    // emulation
    PICC picc3{};
    EXPECT_TRUE(picc3.emulate(Type::FeliCaLiteS, kIdm, kPmm));
    EXPECT_TRUE(picc3.validEmulation());
    EXPECT_FALSE(picc3.emulate(Type::FeliCaLite, kIdm, kPmm));
}

TEST(NFC_F, Reg)
{
    REG r{};
    r.regA(0x11223344);
    r.regB(0xA1A2A3A4);
    r.regC(0x0102030405060708ULL);

    EXPECT_EQ(r.regA(), 0x11223344u);
    EXPECT_EQ(r.regB(), 0xA1A2A3A4u);
    EXPECT_EQ(r.regC(), 0x0102030405060708ULL);

    REG o = r;
    REG n = r;
    n.regA(0x00112233);
    n.regB(0x01020304);
    EXPECT_TRUE(can_write_reg(o, n));

    n.regA(0xFFFFFFFF);
    EXPECT_FALSE(can_write_reg(o, n));
}

TEST(NFC_F, BlockPermission)
{
    EXPECT_TRUE(is_read_only_lite(lite::MAC));
    EXPECT_TRUE(is_read_only_lite(lite::SYS_C));
    EXPECT_FALSE(is_read_only_lite(lite::S_PAD1));

    EXPECT_TRUE(is_read_only_lite_s(lite_s::MAC));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::D_ID));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::SYS_C));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::WCNT));
    EXPECT_TRUE(is_read_only_lite_s(lite_s::CRC_CHECK));

    EXPECT_FALSE(can_read_lite(lite_s::RC));
    EXPECT_FALSE(can_read_lite(lite_s::CK));
    EXPECT_TRUE(can_read_lite(lite::S_PAD0));

    EXPECT_FALSE(can_read_lite_s(lite_s::RC));
    EXPECT_FALSE(can_read_lite_s(lite_s::CK));
    EXPECT_TRUE(can_read_lite_s(lite_s::S_PAD0));
}

TEST(NFC_F, CryptoInvalid)
{
    uint8_t out[16]{};
    uint8_t key16[16]{};
    uint8_t key24[24]{};
    uint8_t rc[16]{};
    uint8_t plain[16]{};
    uint8_t block[16]{};
    uint8_t sk1[8]{};
    uint8_t sk2[8]{};

    EXPECT_FALSE(make_session_key(nullptr, key16, rc));
    EXPECT_FALSE(make_session_key(out, nullptr, rc));
    EXPECT_FALSE(make_session_key(out, key16, nullptr));

    EXPECT_FALSE(generate_mac(nullptr, plain, sizeof(plain), block, sizeof(block), sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, nullptr, sizeof(plain), block, sizeof(block), sk1, sk2, rc));
    EXPECT_TRUE(generate_mac(out, plain, 0, block, sizeof(block), sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), nullptr, sizeof(block), sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, 0, sk1, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, sizeof(block), nullptr, sk2, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, sizeof(block), sk1, nullptr, rc));
    EXPECT_FALSE(generate_mac(out, plain, sizeof(plain), block, sizeof(block), sk1, sk2, nullptr));

    EXPECT_FALSE(make_personalized_card_key_lite_s(nullptr, key24, block));
    EXPECT_FALSE(make_personalized_card_key_lite_s(out, nullptr, block));
    EXPECT_FALSE(make_personalized_card_key_lite_s(out, key24, nullptr));
}
