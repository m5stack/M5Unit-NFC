/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_b.hpp
  @brief Common layer for NFC-B

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_B_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_B_HPP

#include "nfc/layer/nfc_layer.hpp"
#include "nfc/b/nfcb.hpp"
#include "nfc/isoDEP/isoDEP.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include <vector>
#include <memory>

namespace m5 {

namespace unit {
class UnitST25R3916;
class CapST25R3916;
}  // namespace unit
namespace nfc {

/*!
  @class NFCLayerB
  @brief Common interface layer for each chip of the NFC-V reader
 */
class NFCLayerB : public NFCLayerInterface {
public:
    struct Adapter;
    explicit NFCLayerB(m5::unit::UnitST25R3916& u);
    explicit NFCLayerB(m5::unit::CapST25R3916& u);

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) override;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) override;
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms) override;
    virtual m5::nfc::isodep::IsoDEP* isoDEP() override
    {
        return &_isoDEP;
    }
    virtual uint16_t maximum_fifo_depth() const override;

    /*!
      @brief Is the specified PICC currently active?
      @param picc PICC to check
      @return True if this PICC is the one currently selected (ACTIVE state)
    */
    inline bool isActive(const m5::nfc::b::PICC& picc) const
    {
        return _activePICC.valid() && _activePICC == picc;
    }
    /*!
      @brief Retrieve the currently activated PICC
      @return Active PICC
      @note Returns an empty PICC if no PICC is selected (no ACTIVE state)
    */
    const m5::nfc::b::PICC& activatedPICC() const
    {
        return _activePICC;
    }

    ///@name Detection and activation
    ///@{
    /*!
      @brief Send REQB to discover a PICC in IDLE
      @param[out] atqb ATQB received from PICC (at atqb_len)
      @param[in/out] in:atqb length out:actual received length
      @param afi Application Family Identifier (0x00 all)
      @param slots Number of slots required
      @return True if successful
      @note The ATQB per one of the PICC is 11 bytes
      @post PICC transitions: IDLE -> READY on successful response
     */
    inline bool request(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi = 0x00,
                        const m5::nfc::b::Require slots = m5::nfc::b::Require::Slot1)
    {
        return request_wakeup(atqb, atqb_len, afi, slots, false);
    }
    /*!
      @brief Send WUPB to wake a PICC from IDLE or HALT
      @param[out] atqb ATQB received from PICC (at least atqb_len)
      @param[in/out] in:atqb length out:actual received length
      @param afi Application Family Identifier (0x00 all)
      @param slots Number of slots required
      @return True if successful
      @note The ATQB per one of the PICC is 11 bytes
      @post PICC transitions: IDLE/HALT -> READY on successful response
     */
    inline bool wakeup(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi = 0x00,
                       const m5::nfc::b::Require slots = m5::nfc::b::Require::Slot1)
    {
        return request_wakeup(atqb, atqb_len, afi, slots, true);
    }

    /*!
      @brief Detect single idle PICC
      @param[out] picc Detected PICC
      @param afi Application Family Identifier (0x00 all)
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note The detected PICC is typically put into HALT during enumeration to allow discovering others
     */
    bool detect(m5::nfc::b::PICC& picc, const uint8_t afi = 0x00, const uint32_t timeout_ms = 100U);
    /*!
      @brief Detect idle PICCs
      @param[out] piccs Detected PICC PICCs (one per activated PICC candidate)
      @param afi Application Family Identifier (0x00 all)
      @param max_picc How many to detect
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note The detected PICC is typically put into HALT during enumeration to allow discovering others
     */
    bool detect(std::vector<m5::nfc::b::PICC>& piccs, const uint8_t afi = 0x00, const uint8_t max_piccs = 4,
                const uint32_t timeout_ms = 1000U);

    /*!
     */
    bool select(m5::nfc::b::PICC& picc);
#if 0
    bool activate(m5::nfc::b::PICC& picc);
    bool reactivate(const m5::nfc::b::PICC& picc);
    inline bool reactivate()
    {
        return reactivate(_activePICC);
    }
#endif

    ///@}

    ///@name For activated PICC
    ///@{
    bool hlt(const uint8_t pupi[4]);
    bool deselect(const uint8_t pupi[4], const uint8_t cid = 0xFF);
    bool deactivate();
    ///@}

protected:
    bool request_wakeup(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi, const m5::nfc::b::Require slots,
                        const bool wakeup);

    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr) override
    {
        return false;
    }
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) override
    {
        return false;
    }
    inline virtual uint16_t first_user_block() const override
    {
        return 0;
    }
    inline virtual uint16_t last_user_block() const override
    {
        return 0;
    }
    inline virtual uint16_t user_area_size() const
    {
        return 0;
    }
    inline virtual uint16_t unit_size_read() const override
    {
        return 0;
    }
    inline virtual uint16_t unit_size_write() const override
    {
        return 0;
    }

protected:
    m5::nfc::b::PICC _activePICC{};
    m5::nfc::ndef::NDEFLayer _ndef;
    m5::nfc::isodep::IsoDEP _isoDEP;

private:
    std::unique_ptr<Adapter> _impl;
};

///@cond
// Impl for units
struct NFCLayerB::Adapter {
    virtual ~Adapter() = default;

    virtual uint16_t max_fifo_depth() const = 0;

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms)                                         = 0;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) = 0;
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)             = 0;
};
///@endcond

}  // namespace nfc
}  // namespace m5

#endif
