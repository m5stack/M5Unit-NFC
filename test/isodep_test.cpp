/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for ISO-DEP helpers
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/isoDEP/isoDEP.hpp"

using namespace m5::nfc::isodep;
using namespace m5::nfc::isodep::detail;

TEST(IsoDEP, FsciToFsc)
{
    EXPECT_EQ(fsci_to_fsc(0), 16u);
    EXPECT_EQ(fsci_to_fsc(8), 256u);
    EXPECT_EQ(fsci_to_fsc(9), 0u);
}

TEST(IsoDEP, ConfigHelpers)
{
    config_t cfg{};
    cfg.fsc              = 64;
    cfg.pcd_max_frame_tx = 40;
    cfg.pcd_max_frame_rx = 80;

    EXPECT_EQ(cfg.overhead(), 1u);
    EXPECT_EQ(cfg.max_frame_cap_tx(), 37u);  // 40 - overhead(1) - 2
    EXPECT_EQ(cfg.max_frame_size_rx(), 64u);
    EXPECT_EQ(cfg.fsc_inf_cap(), 63u);

    cfg.use_cid = true;
    cfg.use_nad = true;
    EXPECT_EQ(cfg.overhead(), 3u);
    EXPECT_EQ(cfg.max_frame_cap_tx(), 35u);  // 40 - overhead(3) - 2
    EXPECT_EQ(cfg.fsc_inf_cap(), 61u);

    cfg.fsc              = 2;
    cfg.pcd_max_frame_tx = 2;
    EXPECT_EQ(cfg.max_frame_cap_tx(), 0u);
    EXPECT_EQ(cfg.fsc_inf_cap(), 0u);
}

TEST(IsoDEP, PCBHelpers)
{
    EXPECT_TRUE(is_i_block(0x02));
    EXPECT_FALSE(is_i_block(0xA2));
    EXPECT_TRUE(is_r_block(0xA2));
    EXPECT_FALSE(is_r_block(0x02));
    EXPECT_TRUE(is_s_block(0xF2));
    EXPECT_FALSE(is_s_block(0x02));

    EXPECT_TRUE(i_has_more(0x12));
    EXPECT_FALSE(i_has_more(0x02));
    EXPECT_EQ(i_bn(0x02), 0u);
    EXPECT_EQ(i_bn(0x03), 1u);

    EXPECT_TRUE(is_s_wtx(0xF2));
    EXPECT_FALSE(is_s_wtx(0xC0));

    EXPECT_TRUE(is_valid_rblock(0xA2));
    EXPECT_TRUE(is_valid_rblock(0xA3));
    EXPECT_FALSE(is_valid_rblock(0x80));
    EXPECT_FALSE(is_valid_rblock(0x90));

    EXPECT_TRUE(r_is_ack(0xA2));
    EXPECT_TRUE(r_is_nak(0xB2));

    EXPECT_EQ(get_wtxm(0x00), 0u);
    EXPECT_EQ(get_wtxm(0x7F), 0x3Fu);
    EXPECT_FALSE(is_valid_wtxm(0));
    EXPECT_TRUE(is_valid_wtxm(1));
    EXPECT_TRUE(is_valid_wtxm(59));
    EXPECT_FALSE(is_valid_wtxm(60));
}

TEST(IsoDEP, PCBMake)
{
    const uint8_t pcb = make_i_pcb(1, true, true, true);
    EXPECT_EQ(pcb, 0x1Fu);

    EXPECT_EQ(make_i_pcb(0, false, false, false), 0x02);
    EXPECT_EQ(make_r_ack(0, false), 0xA2);
    EXPECT_EQ(make_r_ack(1, true), 0xAB);
    EXPECT_EQ(make_s_wtx_ack(false), 0xF2);
    EXPECT_EQ(make_s_wtx_ack(true), 0xFA);
}

TEST(IsoDEP, MulClamp)
{
    EXPECT_EQ(mul_clamp_u32(0, 10, 100), 0u);
    EXPECT_EQ(mul_clamp_u32(10, 0, 100), 0u);
    EXPECT_EQ(mul_clamp_u32(10, 5, 100), 50u);
    EXPECT_EQ(mul_clamp_u32(10, 20, 100), 100u);
    EXPECT_EQ(mul_clamp_u32(0xFFFFFFFFu, 2, 0xFFFFFFFFu), 0xFFFFFFFFu);
}

TEST(IsoDEP, FwiToMs)
{
    EXPECT_EQ(fwi_to_ms(15, 13.56e6f), 0u);
    EXPECT_GT(fwi_to_ms(0, 13.56e6f), 0u);
    EXPECT_GT(fwi_to_ms(5, 13.56e6f), 0u);
}
