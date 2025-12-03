/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC-F
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include <M5Utility.hpp>
#include "nfc/f/nfcf.hpp"
#include <cstring>

using namespace m5::nfc;
using namespace m5::nfc::f;

namespace {

constexpr Type type_table[] = {
    Type::Unknown, Type::FeliCaStandard, Type::FeliCaLite, Type::FeliCaLiteS, Type::FeliCaPlug,
    //    FeliCaLink,
};
constexpr TimeSlot time_slot_table[]    = {TimeSlot::Slot1, TimeSlot::Slot2, TimeSlot::Slot4, TimeSlot::Slot8,
                                           TimeSlot::Slot16};
constexpr block_t block_table[]         = {0x00, 0xFF, 0x100, 0xFFFF};
constexpr uint32_t block_number_table[] = {0x00, 0xFF, 0x100, 0xFFFF};

}  // namespace

TEST(NFC_F, Basic)
{
    //
    {
        for (auto&& t : type_table) {
            auto ftag = get_nfc_forum_tag_type(t);
            if (t == Type::Unknown) {
                EXPECT_EQ(ftag, NFCForumTag::None);
            } else {
                EXPECT_EQ(ftag, NFCForumTag::Type3);
            }
        }
    }

    //
    {
        uint16_t idx{};
        for (auto&& ts : time_slot_table) {
            auto slots = timeslot_to_slot(ts);
            EXPECT_EQ(slots, 1U << idx);
            ++idx;
        }
    }

    //
    {
        uint32_t idx{};
        for (auto&& b : block_table) {
            auto bnum = b.block();
            auto num  = block_number_table[idx];
            EXPECT_EQ(bnum, num);
            if (num < 0x100) {
                EXPECT_TRUE(b.is_2byte());
                EXPECT_FALSE(b.is_3byte());
            } else {
                EXPECT_FALSE(b.is_2byte());
                EXPECT_TRUE(b.is_3byte());
            }
            EXPECT_EQ(b.access_mode(), 0u);
            EXPECT_EQ(b.order(), 0u);

            uint8_t buf[3]{};
            auto len = b.store(buf);
            EXPECT_EQ(len, b.is_2byte() ? 2 : 3);
            EXPECT_EQ(buf[0], b.is_2byte() ? 0x80 : 0x00);
            EXPECT_EQ(buf[1], bnum & 0xFF);
            EXPECT_EQ(buf[2], bnum >> 8);

            ++idx;
        }

        block_t b{0x12, 0x07, 0x0C};
        EXPECT_EQ(b.block(), 0x12);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0C);

        b.access_mode(0);
        EXPECT_EQ(b.block(), 0x12);
        EXPECT_EQ(b.access_mode(), 0);
        EXPECT_EQ(b.order(), 0x0C);

        b.access_mode(0xFF);
        EXPECT_EQ(b.block(), 0x12);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0C);

        b.order(0);
        EXPECT_EQ(b.block(), 0x12);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0);

        b.order(0xFF);
        EXPECT_EQ(b.block(), 0x12);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0F);

        b.block(0);
        EXPECT_TRUE(b.is_2byte());
        EXPECT_FALSE(b.is_3byte());
        EXPECT_EQ(b.block(), 0);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0F);

        b.block(0XFFFF);
        EXPECT_FALSE(b.is_2byte());
        EXPECT_TRUE(b.is_3byte());
        EXPECT_EQ(b.block(), 0XFFFF);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0F);

        b.block(0XFF);
        EXPECT_TRUE(b.is_2byte());
        EXPECT_FALSE(b.is_3byte());
        EXPECT_EQ(b.block(), 0XFF);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0F);

        b.block(0X100);
        EXPECT_FALSE(b.is_2byte());
        EXPECT_TRUE(b.is_3byte());
        EXPECT_EQ(b.block(), 0X100);
        EXPECT_EQ(b.access_mode(), 0x07);
        EXPECT_EQ(b.order(), 0x0F);
    }
}
