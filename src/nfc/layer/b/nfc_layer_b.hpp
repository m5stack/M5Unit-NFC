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
class UnitWS1850S;
}  // namespace unit
namespace nfc {

/*!
  @class NFCLayerB
  @brief Common interface layer for each chip of the NFC-B reader
 */
class NFCLayerB : public NFCLayerInterface {
public:
    struct Adapter;
    /*!
      @brief Constructor with UnitST25R3916
      @param u UnitST25R3916 instance
     */
    explicit NFCLayerB(m5::unit::UnitST25R3916& u);
    /*!
      @brief Constructor with CapST25R3916 (SPI variant)
      @param u CapST25R3916 instance
     */
    explicit NFCLayerB(m5::unit::CapST25R3916& u);
    /*!
      @brief Constructor with UnitWS1850S (M5Unit-RFID)
      @param u UnitWS1850S instance
     */
    explicit NFCLayerB(m5::unit::UnitWS1850S& u);
    /*!
      @brief Constructor with a chip adapter
      @param adapter Adapter that drives the chip
      @note Lets a chip this library does not know about be used without editing this header. The
      layer takes ownership of the adapter
      @warning The adapter must not be null
     */
    explicit NFCLayerB(std::unique_ptr<Adapter> adapter);
    virtual ~NFCLayerB();

    /*!
      @brief Transceive (NFC-B)
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if successful
     */
    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) override;
    /*!
      @brief Transmit (NFC-B)
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if successful
     */
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) override;
    /*!
      @brief Receive (NFC-B)
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param timeout_ms Timeout in milliseconds
      @return True if successful
     */
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms) override;
    /*!
      @brief Get ISO-DEP context
      @return Pointer to ISO-DEP context
     */
    virtual m5::nfc::isodep::IsoDEP* isoDEP() override
    {
        return &_isoDEP;
    }
    /*!
      @brief Maximum FIFO depth in bytes
      @return Maximum FIFO depth in bytes
     */
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
      @param[in/out] atqb_len in:atqb length out:actual received length
      @param afi Application Family Identifier (0x00 all)
      @param slots Number of slots required
      @param timeout_ms Timeout in milliseconds
      @return True if successful
      @note The ATQB per one of the PICC is 11 bytes
      @post PICC transitions: IDLE -> READY on successful response
     */
    inline bool request(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi = 0x00,
                        const m5::nfc::b::Require slots = m5::nfc::b::Require::Slot1,
                        const uint32_t timeout_ms       = m5::nfc::b::TIMEOUT_REQ_WUP_B)
    {
        return request_wakeup(atqb, atqb_len, afi, slots, false, timeout_ms);
    }
    /*!
      @brief Send WUPB to wake a PICC from IDLE or HALT
      @param[out] atqb ATQB received from PICC (at least atqb_len)
      @param[in/out] atqb_len in:atqb length out:actual received length
      @param afi Application Family Identifier (0x00 all)
      @param slots Number of slots required
      @param timeout_ms Timeout in milliseconds
      @return True if successful
      @note The ATQB per one of the PICC is 11 bytes
      @post PICC transitions: IDLE/HALT -> READY on successful response
     */
    inline bool wakeup(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi = 0x00,
                       const m5::nfc::b::Require slots = m5::nfc::b::Require::Slot1,
                       const uint32_t timeout_ms       = m5::nfc::b::TIMEOUT_REQ_WUP_B)
    {
        return request_wakeup(atqb, atqb_len, afi, slots, true, timeout_ms);
    }

    /*!
      @brief Detect single idle PICC
      @param[out] picc Detected PICC
      @param afi Application Family Identifier (0x00 all)
      @param timeout_ms  Polling time budget in milliseconds
      @param req_timeout_ms Timeout for each REQB/WUPB request in milliseconds
      @return True if detected
      @note The detected PICC is typically put into HALT during enumeration to allow discovering others
     */
    bool detect(m5::nfc::b::PICC& picc, const uint8_t afi = 0x00, const uint32_t timeout_ms = 50U,
                const uint32_t req_timeout_ms = m5::nfc::b::TIMEOUT_REQ_WUP_B);
    /*!
      @brief Detect idle PICCs
      @param[out] piccs Detected PICCs (one per activated PICC candidate)
      @param afi Application Family Identifier (0x00 all)
      @param max_picc How many to detect
      @param timeout_ms  Polling time budget in milliseconds
      @param req_timeout_ms Timeout for each REQB/WUPB request in milliseconds
      @return True if detected
      @note The detected PICC is typically put into HALT during enumeration to allow discovering others
     */
    bool detect(std::vector<m5::nfc::b::PICC>& piccs, const uint8_t afi = 0x00, const uint8_t max_piccs = 4,
                const uint32_t timeout_ms = 1000U, const uint32_t req_timeout_ms = m5::nfc::b::TIMEOUT_REQ_WUP_B);

    /*!
      @brief Send ATTRIB to activate the PICC
      @param picc PICC to activate
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool select(m5::nfc::b::PICC& picc, const uint32_t timeout_ms = m5::nfc::b::TIMEOUT_ATTRIB);
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
    /*!
      @brief Halt (HLTB) the specified PICC
      @param pupi PUPI (4 bytes)
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool hlt(const uint8_t pupi[4], const uint32_t timeout_ms = m5::nfc::b::TIMEOUT_HLTB);
    /*!
      @brief Deselect (S(DESELECT)) the specified PICC
      @param pupi PUPI (4 bytes)
      @param cid CID (0xFF if not used)
      @param timeout_ms Timeout(ms)
      @return True if successful
     */
    bool deselect(const uint8_t pupi[4], const uint8_t cid = 0xFF,
                  const uint32_t timeout_ms = m5::nfc::b::TIMEOUT_DESELECT);
    /*!
      @brief Deactivate the currently active PICC
      @return True if successful
     */
    bool deactivate();
    ///@}

protected:
    bool request_wakeup(uint8_t* atqb, uint16_t& atqb_len, const uint8_t afi, const m5::nfc::b::Require slots,
                        const bool wakeup, const uint32_t timeout_ms = m5::nfc::b::TIMEOUT_REQ_WUP_B);

    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint16_t saddr) override
    {
        return false;
    }
    virtual bool write(const uint16_t saddr, const uint8_t* tx, const uint16_t tx_len) override
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
    inline virtual uint16_t user_area_size() const override
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

/*!
  @struct NFCLayerB::Adapter
  @brief Chip interface for NFC-B
  @note Implement this to drive a chip this library does not know about, then hand it to
  NFCLayerB(std::unique_ptr<Adapter>)
 */
struct NFCLayerB::Adapter {
    virtual ~Adapter() = default;

    /*!
      @brief Maximum FIFO depth in bytes
      @return Maximum FIFO depth in bytes
      @note Answers NFCLayerB::maximum_fifo_depth(), which spells the same thing in full
     */
    virtual uint16_t max_fifo_depth() const = 0;

    /*!
      @brief Send a frame and wait for the answer
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if an answer came back
      @note The layer hands over frames without a CRC_B, so the chip has to add it
      @warning The answer is expected to still carry its CRC_B, and rx_len caps how much of it is
      kept. The ATQB handling reads those two bytes to tell a collision from a good answer, so a
      chip that strips the CRC itself has to put it back
     */
    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) = 0;
    /*!
      @brief Send a frame without waiting for an answer
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if the frame went out
     */
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) = 0;
    /*!
      @brief Receive a frame that was not asked for by transceive()
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param timeout_ms Timeout in milliseconds
      @return True if a frame came in
     */
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms) = 0;
};

}  // namespace nfc
}  // namespace m5

#endif
