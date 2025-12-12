/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_v.hpp
  @brief Common layer for NFC-V related units

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: ISO14443-3 state names

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_V_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_V_HPP

#include "nfc/v/nfcv.hpp"
#include "ndef_layer.hpp"
#include <vector>
#include <memory>

namespace m5 {

namespace unit {
class UnitST25R3916;
class CapST25R3916;

namespace nfc {

/*!
  @class NFCLayerV
  @brief Common interface layer for each chip of the NFC-V reader
 */
class NFCLayerV : public m5::nfc::NFCLayerInterface {
public:
    struct Adapter;
    explicit NFCLayerV(UnitST25R3916& u);
    explicit NFCLayerV(CapST25R3916& u);

    /*!
      @brief Is the specified PICC currently active?
      @param picc PICC to check
      @return True if this PICC is the one currently selected (SELECTED state)
    */
    inline bool isActive(const m5::nfc::v::PICC& picc) const
    {
        return _activePICC.valid() && _activePICC == picc;
    }
    /*!
      @brief Retrieve the currently activated PICC
      @return Active PICC
      @note Returns an empty PICC if no PICC is selected (no SELECTED state)
    */
    const m5::nfc::v::PICC& activatedPICC() const
    {
        return _activePICC;
    }

    ///@name Detection and activation
    ///@{
    /*!
      @brief Detect single ready PICC
      @param[out] picc Detected PICC
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note The detected PICC is typically put into QUIET during enumeration to allow discovering others
     */
    bool detect(m5::nfc::v::PICC& picc, const uint32_t timeout_ms = 50U);
    /*!
      @brief Detect ready PICCs
      @param[out] piccs Detected PICC PICCs
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note The detected PICC is typically put into QUIET during enumeration to allow discovering others
     */
    bool detect(std::vector<m5::nfc::v::PICC>& piccs, const uint32_t timeout_ms = 1000U);

    /*!
      @brief Activate a specific PICC
      @param picc PICC
      @return True if successful
      @pre PICC is READY state
      @post PICC transitions: READY/QUIET -> SELECTED on a successful response
     */
    bool activate(const m5::nfc::v::PICC& picc);
    inline bool reactivate(const m5::nfc::v::PICC& picc)
    {
        return activate(picc);
    }
    inline bool reactivate()
    {
        return reactivate(_activePICC);
    }
    ///@}

    ///@name For activated PICC
    ///@{
    /*!
      @brief Send Reset to ready  to the currently selected PICC (deactivate)
      @return True if successful
      @pre A PICC is in the SELECTED state
      @post PICC transitions: SELECTED -> READY on a successful response
     */
    bool deactivate();
    /*!
      @brief Read single block
      @param[out] rx Output buffer (At least the size of one PICC block)
      @param block Block address (0-255)
      @return True if successful
      @warning The required size varies depending on the PICC
      @warning The maximum is 32
     */
    bool readBlock(uint8_t rx[32], const uint8_t block);

    /*!
      @brief Dump all blocks
      @return True if successful
     */
    bool dump();
    /*!
      @brief Dump 1 block
      @param addr Block address
      @return True if successful
    */
    bool dump(const uint8_t block);

    ///@}

protected:
    bool dump_all();
    bool dump_block(const uint8_t block);

protected:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr) override;
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) override;
    virtual uint16_t firstUserBlock() const override;
    virtual uint16_t lastUserBlock() const override;
    inline virtual uint16_t userBlockUnitSize() const override
    {
        return _activePICC.block_size;
    }

    bool detect_single(m5::nfc::v::PICC& picc);

protected:
    m5::nfc::v::PICC _activePICC{};

private:
    std::unique_ptr<Adapter> _impl;
    m5::nfc::ndef::NDEFLayer _ndef;
};

///@cond
// Impl for units
struct NFCLayerV::Adapter {
    virtual ~Adapter() = default;

    // virtual uint16_t max_fifo_depth() = 0;

    virtual bool inventory(std::vector<m5::nfc::v::PICC>& piccs)                                  = 0;
    virtual bool stay_quiet(const m5::nfc::v::PICC& picc)                                         = 0;
    virtual bool select(const m5::nfc::v::PICC& picc)                                             = 0;
    virtual bool reset_to_ready()                                                                 = 0;
    virtual bool get_system_information(m5::nfc::v::PICC& picc)                                   = 0;
    virtual bool read_single_block(uint8_t rx[32], const uint8_t block)                           = 0;
    virtual bool write_single_block(const uint8_t block, const uint8_t* tx, const uint8_t tx_len) = 0;
};
///@endcond

}  // namespace nfc
}  // namespace unit
}  // namespace m5
#endif
