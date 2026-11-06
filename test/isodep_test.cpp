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
#include "nfc/layer/nfc_layer.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

using namespace m5::nfc::isodep;
using namespace m5::nfc::isodep::detail;

namespace {

class ScriptedLayer : public m5::nfc::NFCLayerInterface {
public:
    explicit ScriptedLayer(std::vector<std::vector<uint8_t>> responses) : _responses{std::move(responses)}
    {
    }

    uint16_t maximum_fifo_depth() const override
    {
        return MAX_FRAME_SIZE;
    }

    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                    const uint32_t timeout_ms) override
    {
        _requests.emplace_back(tx, tx + tx_len);
        _timeouts.push_back(timeout_ms);
        if (_response_index >= _responses.size() || rx_len < _responses[_response_index].size()) {
            return false;
        }
        const auto& response = _responses[_response_index++];
        memcpy(rx, response.data(), response.size());
        rx_len = static_cast<uint16_t>(response.size());
        return true;
    }

    bool receive(uint8_t*, uint16_t&, const uint32_t) override
    {
        return false;
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

    const std::vector<std::vector<uint8_t>>& requests() const
    {
        return _requests;
    }

    const std::vector<uint32_t>& timeouts() const
    {
        return _timeouts;
    }

private:
    std::vector<std::vector<uint8_t>> _responses;
    std::vector<std::vector<uint8_t>> _requests;
    std::vector<uint32_t> _timeouts;
    size_t _response_index{};
};

config_t test_config()
{
    config_t cfg{};
    cfg.fsc              = 64;
    cfg.pcd_max_frame_tx = 64;
    cfg.pcd_max_frame_rx = 64;
    cfg.rx_crc           = false;
    return cfg;
}

}  // namespace

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

TEST(IsoDEP, ResponseChainingUsesNextExpectedBlockNumberAndSyncsSession)
{
    ScriptedLayer layer({{make_i_pcb(0, true, false, false), 0xAA},
                         {make_i_pcb(1, false, false, false), 0xBB},
                         {make_i_pcb(1, false, false, false), 0xCC}});
    IsoDEP iso_dep{layer, test_config()};

    std::array<uint8_t, 8> rx{};
    uint16_t rx_len = rx.size();
    const std::array<uint8_t, 1> first_tx{0xCA};

    EXPECT_TRUE(iso_dep.transceiveINF(rx.data(), rx_len, first_tx.data(), first_tx.size()));
    EXPECT_EQ(rx_len, 2u);
    EXPECT_EQ(rx[0], 0xAA);
    EXPECT_EQ(rx[1], 0xBB);

    EXPECT_EQ(layer.requests().size(), 2u);
    if (layer.requests().size() >= 2u) {
        EXPECT_EQ(layer.requests()[0][0], make_i_pcb(0, false, false, false));
        EXPECT_EQ(layer.requests()[1][0], make_r_ack(1, false));
    }

    rx_len = rx.size();
    const std::array<uint8_t, 1> second_tx{0xCB};
    EXPECT_TRUE(iso_dep.transceiveINF(rx.data(), rx_len, second_tx.data(), second_tx.size()));

    EXPECT_EQ(layer.requests().size(), 3u);
    if (layer.requests().size() >= 3u) {
        EXPECT_EQ(layer.requests()[2][0], make_i_pcb(0, false, false, false));
    }
}

TEST(IsoDEP, OverrideFwtUsedAsTimeout)
{
    ScriptedLayer layer({{make_i_pcb(0, false, false, false), 0xBB}});
    IsoDEP iso{layer, test_config()};

    uint8_t rx[64]{};
    uint16_t rx_len = sizeof(rx);
    const uint8_t cmd[]{0x00};

    policy_t p{1234u, 5000u, 2};  // per-call override
    EXPECT_TRUE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, &p));

    EXPECT_GE(layer.timeouts().size(), 1u);  // bounds guard before indexing
    if (layer.timeouts().size() >= 1u) {
        EXPECT_EQ(layer.timeouts()[0], 1234u);  // override fwt_ms used as the transceive timeout
    }
    EXPECT_EQ(rx_len, 1u);
    EXPECT_EQ(rx[0], 0xBBu);
}

TEST(IsoDEP, NullOverrideFallsBackToConfigTimeout)
{
    ScriptedLayer layer({{make_i_pcb(0, false, false, false), 0xCC}});
    config_t cfg = test_config();
    cfg.fwt_ms   = 777u;
    IsoDEP iso{layer, cfg};

    uint8_t rx[64]{};
    uint16_t rx_len = sizeof(rx);
    const uint8_t cmd[]{0x00};

    EXPECT_TRUE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, nullptr));

    EXPECT_GE(layer.timeouts().size(), 1u);  // bounds guard
    if (layer.timeouts().size() >= 1u) {
        EXPECT_EQ(layer.timeouts()[0], 777u);  // config fwt_ms used when override is null
    }
}

TEST(IsoDEP, MaxRetriesOverrideControlsResend)
{
    // An empty response makes transceiveINF see rlen<1, which enters the
    // "if (retries++ < max_retries) resend" path.
    {
        ScriptedLayer layer({std::vector<uint8_t>{}});  // one empty response
        IsoDEP iso{layer, test_config()};
        uint8_t rx[64]{};
        uint16_t rx_len = sizeof(rx);
        const uint8_t cmd[]{0x00};

        policy_t p{100u, 5000u, 0};  // max_retries=0 -> no resend
        EXPECT_FALSE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, &p));
        EXPECT_EQ(layer.requests().size(), 1u);  // exactly one transceive attempt
    }
    {
        ScriptedLayer layer({std::vector<uint8_t>{}});  // one empty response, then queue is empty
        IsoDEP iso{layer, test_config()};
        uint8_t rx[64]{};
        uint16_t rx_len = sizeof(rx);
        const uint8_t cmd[]{0x00};

        policy_t p{100u, 5000u, 2};  // max_retries=2 -> resend attempted
        EXPECT_FALSE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, &p));
        EXPECT_GT(layer.requests().size(), 1u);  // resent at least once
    }
}

TEST(IsoDEP, FailurePathKeepsWithinCallerCapacity)
{
    // transceive() leaves rx_len at the requested capacity when it fails before receiving, and that
    // capacity comes from the FSC, not from the caller's buffer. The failure path must not copy
    // more than the caller asked for.
    ScriptedLayer layer({});  // empty queue: transceive fails without touching rx_len
    IsoDEP iso{layer, test_config()};
    uint8_t rx[2]{};
    uint16_t rx_len = sizeof(rx);
    const uint8_t cmd[]{0x00};

    EXPECT_FALSE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd)));
    EXPECT_LE(rx_len, static_cast<uint16_t>(sizeof(rx)));
}

TEST(IsoDEP, OverrideDoesNotResetBlockNumber)
{
    // Response I-block BN echoes the request BN, so the PCD block number toggles 0,1,0
    // across three calls. The per-call override (2nd call) must NOT disturb that.
    ScriptedLayer layer({{make_i_pcb(0, false, false, false), 0x11},
                         {make_i_pcb(1, false, false, false), 0x22},
                         {make_i_pcb(0, false, false, false), 0x33}});
    IsoDEP iso{layer, test_config()};

    uint8_t rx[64]{};
    uint16_t rx_len = sizeof(rx);
    const uint8_t cmd[]{0x00};

    rx_len = sizeof(rx);
    EXPECT_TRUE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, nullptr));  // 1st: no override

    policy_t p{2000u, 5000u, 1};
    rx_len = sizeof(rx);
    EXPECT_TRUE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, &p));  // 2nd: WITH override

    rx_len = sizeof(rx);
    EXPECT_TRUE(iso.transceiveINF(rx, rx_len, cmd, sizeof(cmd), nullptr, nullptr));  // 3rd: no override

    EXPECT_GE(layer.requests().size(), 3u);  // bounds guard before indexing
    if (layer.requests().size() >= 3u) {
        EXPECT_EQ(i_bn(layer.requests()[0][0]), 0u);
        EXPECT_EQ(i_bn(layer.requests()[1][0]), 1u);
        EXPECT_EQ(i_bn(layer.requests()[2][0]), 0u);
    }
}
