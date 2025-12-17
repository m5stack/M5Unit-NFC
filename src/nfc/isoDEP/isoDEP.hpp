/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file isoDEP.hpp
  @brief ISO Data Exchange Protocol
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_ISODEP_ISODEP_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_ISODEP_ISODEP_HPP
#include <cstdint>
#include <vector>

namespace m5 {
namespace nfc {
class NFCLayerInterface;
/*!
  @namespace isodep
  @brief For ISO-DEP
 */
namespace isodep {

//! @brief Calculate waiting time(ms) by fwi and fc
uint32_t fwi_to_ms(const uint8_t fwi, const float fc);

struct config_t {
    // PICCが受けられる最大INF（FSC）
    uint16_t fsc{256};

    // PCD側の送受信制約（Unit依存: FIFO/内部バッファ）
    // ISO-DEP フレーム全体(PCB+CID/NAD+INF)をこのサイズ以内に収める
    uint16_t pcd_max_frame_tx{256};
    uint16_t pcd_max_frame_rx{256};

    // 待ち（FWT/WTX）は後で詰められるように一旦msで持つ
    uint32_t fwt_ms{100};
    uint32_t wtx_max_ms{5000};

    // ISO-DEPオプション
    bool use_cid{};
    uint8_t cid{};
    bool use_nad{};
    uint8_t nad{};

    uint8_t max_retries{2};
    bool rx_crc{true};  // Remove CRC if true in INF
};

struct RxInfo {
    bool more{};      // Continue chaining?
    bool wtx_seen{};  // WTX?
};

class IsoDEP {
public:
    explicit IsoDEP(NFCLayerInterface& layer) : _tr{layer}
    {
    }
    IsoDEP(NFCLayerInterface& layer, const config_t& c) : _tr{layer}, _cfg{c}
    {
    }

    inline config_t config() const
    {
        return _cfg;
    }
    inline void config(const config_t& cfg)
    {
        _cfg       = cfg;
        _block_num = 0;
    }

    //@brief Transceive INF
    bool transceiveINF(uint8_t* rx_inf, uint16_t& rx_inf_len, const uint8_t* tx_inf, const uint16_t tx_inf_len,
                       RxInfo* info = nullptr);
    //@brief Transceive APDU
    bool transceiveAPDU(uint8_t* rx, uint16_t& rx_len, const uint8_t* cmd, const uint16_t cmd_len);
    //@brief Transceive normal
    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms);

private:
    NFCLayerInterface& _tr;
    config_t _cfg{};
    uint8_t _block_num{};  // I-Block BN (0/1)
};

}  // namespace isodep
}  // namespace nfc
}  // namespace m5
#endif
