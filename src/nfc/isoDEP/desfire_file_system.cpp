/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file desfire_file_system.cpp
  @brief File system base using isoDEP for MIFARE DESFire
*/
#include "desfire_file_system.hpp"
#include "nfc/layer/a/nfc_layer_a.hpp"
#include "nfc/isodep/isoDEP.hpp"
#include "nfc/apdu/apdu.hpp"
#include <cstring>
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::isodep;
using namespace m5::nfc::apdu;

namespace {

}  // namespace

namespace m5 {
namespace nfc {
namespace a {
namespace mifare {
namespace desfire {

std::vector<uint8_t> make_native_wrap_command(const uint8_t ins, const uint8_t* data, const uint16_t data_len)
{
    // Le(0) are always assigned
    const uint8_t lc_len = (data_len == 0) ? 0 : ((data_len > 255) ? 3 : 1);

    std::vector<uint8_t> cmd{};
    cmd.resize(4 + lc_len + data_len + 1);

    uint32_t offset{};

    // ---- Header
    cmd[offset++] = 0x90;
    cmd[offset++] = ins;
    cmd[offset++] = 0x00;
    cmd[offset++] = 0x00;

    // ---- Body
    // Lc
    if (lc_len == 3) {
        cmd[offset++] = 0x00;
        cmd[offset++] = static_cast<uint8_t>((data_len >> 8) & 0xFF);
        cmd[offset++] = static_cast<uint8_t>(data_len & 0xFF);
    } else if (lc_len == 1) {
        cmd[offset++] = static_cast<uint8_t>(data_len & 0xFF);
    }
    // Data
    if (data_len) {
        std::memcpy(cmd.data() + offset, data, data_len);
        offset += data_len;
    }
    cmd[offset++] = 0x00;
    return cmd;
}

DESFireFileSystem::DESFireFileSystem(m5::nfc::NFCLayerA& layer) : FileSystem{layer.isoDEP()}
{
    const auto& picc = layer.activatedPICC();
    // M5_LIB_LOGE(">>>>PICC %s %u", picc.uidAsString().c_str(), picc.valid());

    auto cfg = _isoDEP.config();
    //        cfg.fwt_ms           = fwi_to_ms(picc.fwi(), 13.56e6f);
    //        cfg.fsc              = picc.maximumFrameLength();
    //        cfg.pcd_max_frame_tx = cfg.pcd_max_frame_rx = 256;  // TODO FIFO_DEPTH
    cfg.fwt_ms           = 500;
    cfg.fsc              = 256;
    cfg.pcd_max_frame_tx = cfg.pcd_max_frame_rx = 256;  // TODO FIFO_DEPTH
    _isoDEP.config(cfg);
}

bool DESFireFileSystem::selectApplication(const uint8_t aid[3], const uint32_t timeout_ms)
{
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_SELECT_APPLICATION), aid, 3);
    uint8_t rx[2]{};
    uint16_t rx_len = sizeof(rx);

    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to selectApplication %u", rx_len);
        return false;
    }
    return is_successful(rx, rx_len);
}

bool DESFireFileSystem::selectApplication(const uint32_t aid24, const uint32_t timeout_ms)
{
    uint8_t aid[3]{};
    aid[0] = aid24 >> 16;
    aid[1] = aid24 >> 8;
    aid[2] = aid24 & 0xFF;
    return selectApplication(aid, timeout_ms);
}

bool DESFireFileSystem::getApplicationIDs(std::vector<desfire_aid_t>& out, uint32_t timeout_ms)
{
    out.clear();
    auto cmd = make_native_wrap_command(m5::stl::to_underlying(INS::DF_GET_APPLICATION_IDS));

    uint8_t rx[512]{};
    uint16_t rx_len = sizeof(rx);
    if (!transceive(rx, rx_len, cmd.data(), cmd.size()) || rx_len < 2) {
        M5_LIB_LOGE("Failed to getApplicationIDs %u", rx_len);
        return false;
    }
    if (is_successful(rx, rx_len)) {
        const uint16_t data_len = rx_len - 2;
        if (data_len % 3 != 0) {
            return false;
        }

        const uint16_t n = data_len / 3;
        out.reserve(n);
        for (uint_fast16_t i = 0; i < n; ++i) {
            desfire_aid_t aid{};
            aid.aid[0] = rx[i * 3 + 0];
            aid.aid[1] = rx[i * 3 + 1];
            aid.aid[2] = rx[i * 3 + 2];
            out.emplace_back(aid);
        }
        return true;
    }
    return false;
}

// Support continued reception via 0x91AF
bool DESFireFileSystem::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len)
{
    const auto org_rx_len = rx_len;
    rx_len                = 0;
    if (!rx || org_rx_len < 2 || !tx || tx_len < 4) {
        return false;
    }

    // m5::utility::log::dump(tx, tx_len, false);

    std::vector<uint8_t> acc;
    acc.reserve(org_rx_len);

    std::vector<uint8_t> tmp_rx(org_rx_len);
    uint16_t tmp_rx_len = org_rx_len;

    // First
    if (!_isoDEP.transceiveINF(tmp_rx.data(), tmp_rx_len, tx, tx_len) || tmp_rx_len < 2) {
        M5_LIB_LOGE("Failed to transceiveINF %u", tmp_rx_len);
        // m5::utility::log::dump(tmp_rx.data(), tmp_rx_len, false);
        return false;
    }

    if (tmp_rx_len > 2) {
        if (acc.size() + (tmp_rx_len - 2) + 2 /*status 2bytes*/ > org_rx_len) {
            return false;
        }
        acc.insert(acc.end(), tmp_rx.begin(), tmp_rx.begin() + (tmp_rx_len - 2));
    }

    constexpr uint8_t af_cmd[] = {0x90, 0xAF, 0x00, 0x00, 0x00};
    constexpr uint8_t MAX_AF_FOLLOW{32};
    uint8_t af_follow{};

    while (is_more(tmp_rx.data(), tmp_rx_len)) {
        if (++af_follow > MAX_AF_FOLLOW) {
            return false;
        }
        tmp_rx_len = org_rx_len;
        // More response please!
        if (!_isoDEP.transceiveINF(tmp_rx.data(), tmp_rx_len, af_cmd, sizeof(af_cmd)) || tmp_rx_len < 2) {
            M5_LIB_LOGE("Failed to transceiveINF %u", tmp_rx_len);
            return false;
        }
        // m5::utility::log::dump(tmp_rx.data(), tmp_rx_len, false);

        if (tmp_rx_len > 2) {
            if (acc.size() + (tmp_rx_len - 2) + 2 /*status 2bytes*/ > org_rx_len) {
                return false;
            }
            acc.insert(acc.end(), tmp_rx.begin(), tmp_rx.begin() + (tmp_rx_len - 2));
        }
    }
    acc.push_back(tmp_rx[tmp_rx_len - 2]);
    acc.push_back(tmp_rx[tmp_rx_len - 1]);
    if (acc.size() > org_rx_len) {
        return false;
    }

    rx_len = acc.size();
    std::memcpy(rx, acc.data(), rx_len);
    return true;
}

}  // namespace desfire
}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
