/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for DESFire detail helpers
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/isoDEP/desfire_file_system.hpp"
#include "nfc/layer/nfc_layer.hpp"

using namespace m5::nfc::a::mifare::desfire;
using namespace m5::nfc::a::mifare::desfire::detail;

namespace {

class DummyLayer : public m5::nfc::NFCLayerInterface {
public:
    uint16_t maximum_fifo_depth() const override
    {
        return 256;
    }
    bool read(uint8_t*, uint16_t&, const uint16_t) override
    {
        return false;
    }
    bool write(const uint16_t, const uint8_t*, const uint16_t) override
    {
        return false;
    }
    uint16_t first_user_block() const override
    {
        return 0;
    }
    uint16_t last_user_block() const override
    {
        return 0;
    }
    uint16_t user_area_size() const override
    {
        return 0;
    }
    uint16_t unit_size_read() const override
    {
        return 0;
    }
    uint16_t unit_size_write() const override
    {
        return 0;
    }
};

}  // namespace

TEST(DESFireDetail, PackUnpack24)
{
    uint8_t buf[3]{};
    pack_le24(buf, 0x00123456);
    EXPECT_EQ(buf[0], 0x56);
    EXPECT_EQ(buf[1], 0x34);
    EXPECT_EQ(buf[2], 0x12);
    EXPECT_EQ(unpack_le24(buf), 0x00123456u);

    pack_be24(buf, 0x00ABCDEF);
    EXPECT_EQ(buf[0], 0xAB);
    EXPECT_EQ(buf[1], 0xCD);
    EXPECT_EQ(buf[2], 0xEF);
}

TEST(DESFireDetail, ClampAndCapacity)
{
    EXPECT_EQ(clamp_u16_size(0), 0u);
    EXPECT_EQ(clamp_u16_size(65535), 65535u);
    EXPECT_EQ(clamp_u16_size(65536), 65535u);

    DummyLayer layer{};
    m5::nfc::isodep::IsoDEP dep(layer);
    m5::nfc::isodep::config_t cfg{};
    cfg.fsc              = 128;
    cfg.pcd_max_frame_rx = 64;
    dep.config(cfg);
    EXPECT_EQ(default_rx_capacity(dep), 256u);

    cfg.fsc              = 1024;
    cfg.pcd_max_frame_rx = 512;
    dep.config(cfg);
    EXPECT_EQ(default_rx_capacity(dep), 512u);
}
