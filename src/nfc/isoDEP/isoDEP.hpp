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

constexpr uint16_t MAX_FRAME_SIZE{256};

namespace detail {

inline bool is_i_block(uint8_t pcb)
{
    return (pcb & 0xC0) == 0x00;
}

inline bool is_r_block(uint8_t pcb)
{
    return (pcb & 0xC0) == 0x80;
}

inline bool is_s_block(uint8_t pcb)
{
    return (pcb & 0xC0) == 0xC0;
}

inline bool i_has_more(uint8_t pcb)
{
    return (pcb & 0x10) != 0;
}

inline uint8_t i_bn(uint8_t pcb)
{
    return (pcb >> 0) & 0x01;
}

inline bool is_s_wtx(uint8_t pcb)
{
    return (pcb & 0xC0) == 0xC0 && (pcb & 0x30) == 0x30;  // S-Block & WTX
}

inline bool is_valid_rblock(uint8_t pcb)
{
    // R-Block MUST bits: b6=1, b3=0, b2=1 (mask 0x26, val 0x22), type=0x80
    return ((pcb & 0xC0) == 0x80) && ((pcb & 0x26) == 0x22);
}

inline bool r_is_nak(uint8_t pcb)
{
    return (pcb & 0x10) != 0;  // bit4 distinguishes ACK/NAK (0x10)
}

inline bool r_is_ack(uint8_t pcb)
{
    return !r_is_nak(pcb);
}

inline uint8_t get_wtxm(uint8_t inf)
{
    return inf & 0x3F;
}

inline bool is_valid_wtxm(uint8_t wtxm)
{
    return (wtxm >= 1) && (wtxm <= 59);
}

inline uint32_t mul_clamp_u32(uint32_t a, uint32_t b, uint32_t maxv)
{
    if (!a || !b) {
        return 0;
    }
    if (a > maxv / b) {
        return maxv;
    }
    uint32_t v = a * b;
    return (v > maxv) ? maxv : v;
}

// I-Block PCB
inline uint8_t make_i_pcb(uint8_t bn, bool more, bool has_cid, bool has_nad)
{
    uint8_t pcb = 0x02;  // I-Block base (0x00/0x02?)
    pcb &= ~0x01;
    pcb |= (bn & 0x01);
    pcb |= more ? 0x10 : 0x00;
    pcb |= has_cid ? 0x08 : 0x00;
    pcb |= has_nad ? 0x04 : 0x00;
    return pcb;
}

// R-Block ACK
inline uint8_t make_r_ack(uint8_t bn, bool has_cid)
{
    uint8_t pcb = 0xA2;  // 0xA0 or 0xA2?
    pcb &= ~0x01;
    pcb |= (bn & 0x01);
    pcb |= has_cid ? 0x08 : 0x00;
    return pcb;
}

// S-Block WTX-ACK
inline uint8_t make_s_wtx_ack(bool has_cid)
{
    uint8_t pcb = 0xF2;  // S(WTX)
    pcb |= has_cid ? 0x08 : 0x00;
    return pcb;
}

}  // namespace detail

//! @brief Convert FSCI to FSC (ISO/IEC 14443-4)
inline uint16_t fsci_to_fsc(const uint8_t fsci)
{
    static constexpr uint16_t table[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};
    return (fsci < (sizeof(table) / sizeof(table[0]))) ? table[fsci] : 0;
}

/*!
  @struct config_t
  @brief ISO-DEP configuration
 */
struct config_t {
    uint16_t fsc{};
    uint16_t pcd_max_frame_tx{};
    uint16_t pcd_max_frame_rx{};
    uint32_t fwt_ms{100};
    uint32_t wtx_max_ms{5000};

    // options
    bool use_cid{};
    uint8_t cid{};
    bool use_nad{};
    uint8_t nad{};

    uint8_t max_retries{2};
    bool rx_crc{true};  // Remove CRC if true in INF

    inline uint16_t max_frame_cap_tx() const
    {
        const auto max_frame = std::min<uint16_t>(pcd_max_frame_tx, fsc);
        return (max_frame > (overhead() + 2)) ? (max_frame - overhead() - 2) : 0;
    }
    inline uint16_t max_frame_size_rx() const
    {
        return std::min<uint16_t>(pcd_max_frame_rx, fsc);
    }
    inline uint16_t fsc_inf_cap() const
    {
        return (fsc > overhead()) ? static_cast<uint16_t>(fsc - overhead()) : 0;
    }
    inline uint16_t overhead() const
    {
        return 1 + (use_cid ? 1 : 0) + (use_nad ? 1 : 0);
    }
};

/*!
  @struct RxInfo
  @brief RX information
 */
struct RxInfo {
    bool more{};      // Continue chaining?
    bool wtx_seen{};  // WTX?
};

/*!
  @class IsoDEP
  @brief ISO Data Exchange Protocol
 */
class IsoDEP {
public:
    explicit IsoDEP(NFCLayerInterface& layer) : _layer{layer}
    {
    }
    IsoDEP(NFCLayerInterface& layer, const config_t& c) : _layer{layer}, _cfg{c}
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

    //! @brief Transceive INF
    bool transceiveINF(uint8_t* rx_inf, uint16_t& rx_inf_len, const uint8_t* tx_inf, const uint16_t tx_inf_len,
                       RxInfo* info = nullptr);
    //! @brief Transceive APDU
    bool transceiveAPDU(uint8_t* rx, uint16_t& rx_len, const uint8_t* cmd, const uint16_t cmd_len);
    //! @brief Transceive normal
    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms);

private:
    NFCLayerInterface& _layer;
    config_t _cfg{};
    uint8_t _block_num{};  // I-Block BN (0/1)
};

}  // namespace isodep
}  // namespace nfc
}  // namespace m5
#endif
