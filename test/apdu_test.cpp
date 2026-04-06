/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for APDU
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/apdu/apdu.hpp"
#include <cstring>

using namespace m5::nfc::apdu;

namespace {

constexpr uint8_t cla_sample = 0x00;
constexpr uint8_t ins_sample = 0xA4;

}  // namespace

TEST(APDU, ResponseOk)
{
    EXPECT_TRUE(is_response_OK(0x9000));
    EXPECT_TRUE(is_response_OK(0x6100));
    EXPECT_TRUE(is_response_OK(0x61FF));
    EXPECT_TRUE(is_response_OK(0x9F00));
    EXPECT_TRUE(is_response_OK(0x9F10));
    EXPECT_FALSE(is_response_OK(0x6A82));

    const uint8_t sw_ok[2] = {0x90, 0x00};
    const uint8_t sw_ng[2] = {0x6A, 0x82};
    EXPECT_TRUE(is_response_OK(sw_ok));
    EXPECT_FALSE(is_response_OK(sw_ng));

    EXPECT_TRUE(is_response_OK(0x90, 0x00));
    EXPECT_FALSE(is_response_OK(0x6A, 0x82));
}

TEST(APDU, NeedSelectFileLe)
{
    EXPECT_TRUE(need_select_file_le(0x00));
    EXPECT_TRUE(need_select_file_le(0x08));
    EXPECT_FALSE(need_select_file_le(0x0C));
    EXPECT_FALSE(need_select_file_le(0x0D));
}

TEST(APDU, MakeCommandCases)
{
    // Case 1
    auto c1 = make_apdu_case1(cla_sample, ins_sample, 0x01, 0x02);
    ASSERT_EQ(c1.size(), 4u);
    EXPECT_EQ(c1[0], cla_sample);
    EXPECT_EQ(c1[1], ins_sample);
    EXPECT_EQ(c1[2], 0x01);
    EXPECT_EQ(c1[3], 0x02);

    // Case 2 short Le
    auto c2 = make_apdu_case2(cla_sample, ins_sample, 0x00, 0x00, 0x10);
    ASSERT_EQ(c2.size(), 5u);
    EXPECT_EQ(c2[4], 0x10);

    // Case 2 extended Le (257)
    auto c2e = make_apdu_case2(cla_sample, ins_sample, 0x00, 0x00, 0x101);
    ASSERT_EQ(c2e.size(), 7u);
    EXPECT_EQ(c2e[4], 0x00);
    EXPECT_EQ(c2e[5], 0x01);
    EXPECT_EQ(c2e[6], 0x01);

    // Case 3 short Lc
    uint8_t data3[] = {0xDE, 0xAD, 0xBE, 0xEF};
    auto c3         = make_apdu_case3(cla_sample, ins_sample, 0x00, 0x00, data3, sizeof(data3));
    ASSERT_EQ(c3.size(), 4u + 1u + sizeof(data3));
    EXPECT_EQ(c3[4], sizeof(data3));

    // Case 3 extended Lc
    std::vector<uint8_t> data_long(260, 0xAA);
    auto c3e = make_apdu_case3(cla_sample, ins_sample, 0x00, 0x00, data_long.data(), data_long.size());
    ASSERT_EQ(c3e.size(), 4u + 3u + data_long.size());
    EXPECT_EQ(c3e[4], 0x00);
    EXPECT_EQ(c3e[5], 0x01);
    EXPECT_EQ(c3e[6], 0x04);

    // Case 4 (Lc + Le)
    auto c4 = make_apdu_case4(cla_sample, ins_sample, 0x00, 0x00, data3, sizeof(data3), 0x20);
    ASSERT_EQ(c4.size(), 4u + 1u + sizeof(data3) + 1u);
    EXPECT_EQ(c4.back(), 0x20);

    // data_len > 0 with nullptr should return empty
    auto bad = make_apdu_command(cla_sample, ins_sample, 0x00, 0x00, nullptr, 1, 0);
    EXPECT_TRUE(bad.empty());
}

TEST(APDU, ParseTLV)
{
    // Short tag/length
    const uint8_t buf1[] = {0x5A, 0x03, 0x01, 0x02, 0x03};
    auto tlvs1           = parse_tlv(buf1, sizeof(buf1));
    ASSERT_EQ(tlvs1.size(), 1u);
    EXPECT_EQ(tlvs1[0].tag, 0x5Au);
    EXPECT_EQ(tlvs1[0].len, 3u);
    EXPECT_EQ(tlvs1[0].tag_len, 1u);
    EXPECT_TRUE(std::memcmp(tlvs1[0].v, buf1 + 2, 3) == 0);

    // Extended tag + long length
    const uint8_t buf2[] = {0x1F, 0x81, 0x01, 0x81, 0x03, 0xAA, 0xBB, 0xCC};
    auto tlvs2           = parse_tlv(buf2, sizeof(buf2));
    ASSERT_EQ(tlvs2.size(), 1u);
    EXPECT_EQ(tlvs2[0].tag, 0x1F8101u);
    EXPECT_EQ(tlvs2[0].len, 3u);
    EXPECT_EQ(tlvs2[0].tag_len, 3u);
    EXPECT_TRUE(std::memcmp(tlvs2[0].v, buf2 + 5, 3) == 0);
}

TEST(APDU, ParseTLVInvalid)
{
    // Null/empty
    EXPECT_TRUE(parse_tlv(nullptr, 10).empty());
    EXPECT_TRUE(parse_tlv(nullptr, 0).empty());
    const uint8_t empty[] = {};
    EXPECT_TRUE(parse_tlv(empty, 0).empty());

    // Extended tag continuation beyond limit
    const uint8_t bad_tag[] = {0x1F, 0x81, 0x80, 0x00};
    EXPECT_TRUE(parse_tlv(bad_tag, sizeof(bad_tag)).empty());

    // Invalid length (indefinite/too large)
    const uint8_t bad_len[] = {0x5A, 0x83, 0x00, 0x01, 0x02};
    EXPECT_TRUE(parse_tlv(bad_len, sizeof(bad_len)).empty());

    // Length exceeds buffer
    const uint8_t bad_vlen[] = {0x5A, 0x04, 0x01, 0x02, 0x03};
    EXPECT_TRUE(parse_tlv(bad_vlen, sizeof(bad_vlen)).empty());
}

TEST(APDU, TLVPrimitive)
{
    TLV t{};
    t.tag = 0x20;  // constructed bit set
    EXPECT_TRUE(t.is_constructed());
    EXPECT_FALSE(t.is_primitive());
}

TEST(APDU, TLVPrimitiveClear)
{
    TLV t{};
    t.tag = 0x1F;  // constructed bit clear
    EXPECT_FALSE(t.is_constructed());
    EXPECT_TRUE(t.is_primitive());
}
