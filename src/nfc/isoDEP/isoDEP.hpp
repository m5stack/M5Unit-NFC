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

/*!
  @brief Calculate waiting time(ms) by fwi and fc
  @param fwi Frame Waiting Integer
  @param fc Carrier frequency in Hz (13.56e6f for NFC)
  @return Frame waiting time in milliseconds
 */
uint32_t fwi_to_ms(const uint8_t fwi, const float fc);

constexpr uint16_t MAX_FRAME_SIZE{256};

namespace detail {
///@cond INTERNAL

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

///@endcond
}  // namespace detail

/*!
  @brief Convert FSCI to FSC (ISO/IEC 14443-4)
  @param fsci Frame Size for proximity Card Integer
  @return Frame Size for proximity Card in bytes, or 0 if invalid
 */
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

    /*!
      @brief Maximum INF payload capacity for transmission
      @return Maximum transmittable INF bytes after PCB/CID/NAD and CRC overhead
     */
    inline uint16_t max_frame_cap_tx() const
    {
        const auto max_frame = std::min<uint16_t>(pcd_max_frame_tx, fsc);
        return (max_frame > (overhead() + 2)) ? (max_frame - overhead() - 2) : 0;
    }
    /*!
      @brief Maximum receive frame size
      @return Maximum receive frame size in bytes
     */
    inline uint16_t max_frame_size_rx() const
    {
        return std::min<uint16_t>(pcd_max_frame_rx, fsc);
    }
    /*!
      @brief Maximum INF capacity allowed by FSC
      @return Maximum INF bytes after PCB/CID/NAD overhead
     */
    inline uint16_t fsc_inf_cap() const
    {
        return (fsc > overhead()) ? static_cast<uint16_t>(fsc - overhead()) : 0;
    }
    /*!
      @brief ISO-DEP frame overhead
      @return PCB plus optional CID and NAD byte count
     */
    inline uint16_t overhead() const
    {
        return 1 + (use_cid ? 1 : 0) + (use_nad ? 1 : 0);
    }
};

/*!
  @struct policy_t
  @brief Per-exchange timeout/retry override for transceiveINF/transceiveAPDU
  @note Passed as a per-call override; it does not modify config_t and does not reset the block number
 */
struct policy_t {
    uint32_t fwt_ms{};      //!< Frame waiting time (ms). 0 is clamped to 1 internally
    uint32_t wtx_max_ms{};  //!< Upper bound for WTX extension (ms)
    uint8_t max_retries{};  //!< Number of resends (0 = no resend)

    policy_t() = default;
    /*!
      @brief Construct with explicit values (enables positional brace-init under C++11)
      @param fwt Frame waiting time in milliseconds
      @param wtx Upper bound for WTX extension in milliseconds
      @param retries Number of resends
     */
    policy_t(const uint32_t fwt, const uint32_t wtx, const uint8_t retries)
        : fwt_ms(fwt), wtx_max_ms(wtx), max_retries(retries)
    {
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
    /*!
      @brief Constructor with NFC layer
      @param layer NFC layer interface
     */
    explicit IsoDEP(NFCLayerInterface& layer) : _layer{layer}
    {
    }
    /*!
      @brief Constructor with NFC layer and configuration
      @param layer NFC layer interface
      @param c ISO-DEP configuration
     */
    IsoDEP(NFCLayerInterface& layer, const config_t& c) : _layer{layer}, _cfg{c}
    {
    }

    /*!
      @brief Get configuration
      @return Current ISO-DEP configuration
     */
    inline config_t config() const
    {
        return _cfg;
    }
    /*!
      @brief Set configuration
      @param cfg New ISO-DEP configuration
      @note Resets the ISO-DEP block number
     */
    inline void config(const config_t& cfg)
    {
        _cfg       = cfg;
        _block_num = 0;
    }

    /*!
      @brief Transceive INF
      @param[out] rx_inf Receive INF buffer
      @param[in,out] rx_inf_len In: capacity of rx_inf, Out: received INF length on success
      @param tx_inf Transmit INF buffer
      @param tx_inf_len Transmit INF length
      @param[out] info Optional receive information (chaining/WTX)
      @param override_policy Optional per-call timeout/retry override (nullptr uses config values)
      @return True if succeeded
      @note override_policy applies to this exchange only; it does not persist and does not reset the block number
      @note On a false return rx_inf is not INF and rx_inf_len is only guaranteed not to exceed the
      capacity passed in, so treat rx_inf as INF only when this returns true
     */
    bool transceiveINF(uint8_t* rx_inf, uint16_t& rx_inf_len, const uint8_t* tx_inf, const uint16_t tx_inf_len,
                       RxInfo* info = nullptr, const policy_t* override_policy = nullptr);
    /*!
      @brief Transceive APDU
      @param[out] rx Receive buffer (response + SW)
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param cmd Command APDU
      @param cmd_len Command APDU length
      @param override_policy Optional per-call timeout/retry override (nullptr uses config values)
      @return True if succeeded
      @note override_policy is forwarded to the underlying transceiveINF for this exchange only
     */
    bool transceiveAPDU(uint8_t* rx, uint16_t& rx_len, const uint8_t* cmd, const uint16_t cmd_len,
                        const policy_t* override_policy = nullptr);
    /*!
      @brief Transceive normal
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if succeeded
     */
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
