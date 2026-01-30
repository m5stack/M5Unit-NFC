/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_v.hpp
  @brief Common layer for NFC-V

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_V_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_V_HPP

#include "nfc/layer/nfc_layer.hpp"
#include "nfc/v/nfcv.hpp"
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
  @class NFCLayerV
  @brief Common interface layer for each chip of the NFC-V reader
 */
class NFCLayerV : public NFCLayerInterface {
public:
    struct Adapter;
    explicit NFCLayerV(m5::unit::UnitST25R3916& u);
    explicit NFCLayerV(m5::unit::CapST25R3916& u);

    virtual uint16_t maximum_fifo_depth() const override;

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

    // @brief Get current modulation mode
    inline m5::nfc::v::ModulationMode modulationMode() const
    {
        return _modulation;
    }
    // @brief Set current modulation mode
    inline void setModulationMode(const m5::nfc::v::ModulationMode mode)
    {
        _modulation = mode;
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

    bool reactivate(const m5::nfc::v::PICC& picc);
    inline bool reactivate()
    {
        return reactivate(_activePICC);
    }
    ///@}

    ///@name For activated PICC
    ///@{
    /*!
      @brief Send Reset to ready to the currently selected PICC (deactivate)
      @return True if successful
      @pre A PICC is in the SELECTED state
      @post PICC transitions: SELECTED -> READY on a successful response
     */
    bool deactivate();
    /*!
      @brief Read single block
      @param[out] rx Output buffer (At least the size of one PICC block)
      @param block Block address
      @return True if successful
      @warning The required size varies depending on the PICC
      @warning The maximum rx size is 32
     */
    bool readBlock(uint8_t rx[32], const uint16_t block);
    /*!
      @brief Write single block
      @param block Block address
      @param tx buffer
      @param tx_len buffer size
      @warning If the tx_len is less than the size of one PICC block, the remaining space is filled with 0x00
      @warning If the tx_len is larger than the size of one PICC block, only the first 4 bytes will be written
     */
    bool writeBlock(const uint16_t block, const uint8_t* tx, const uint8_t tx_len);
    /*!
      @brief Read any bytes from user area
      @details Continue reading only the user area from the first block of the user area until rx_len is satisfied
      @param rx Buffer
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param sblock Reading start block
      @return True if successful
     */
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint16_t sblock) override;
    /*!
      @brief Write any bytes to user area
      @details Continue writing only the user area from the first block of the user area until tx_len is satisfied
      @param sblock Writing start block
      @param tx Buffer
      @param tx_len buffer size
      @return True if successful
      @warning The write unit is the size of one block in PICC
     */
    virtual bool write(const uint16_t sblock, const uint8_t* tx, const uint16_t tx_len) override;

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
    bool dump(const uint16_t block);
    ///@}

    ///@note For activated PICC
    ///@name For NDEF
    ///@{
    /*!
      @brief Is the PICC data in NDEF format?
      @paran[out] valid True if NDEF format
      @return True if successful
     */
    bool ndefIsValidFormat(bool& valid);
    /*!
      @brief Read Type5 Capability Container
      @param[out] cc Capability container
      @return True if successful
     */
    bool ndefReadCapabilityContainer(m5::nfc::ndef::type5::CapabilityContainer& cc);
    /*!
      @brief Write Type5 Capability Container
      @param[in] cc Capability container
      @return True if successful
     */
    bool ndefWriteCapabilityContainer(const m5::nfc::ndef::type5::CapabilityContainer& cc);
    /*!
      @brief Read NDEF Message TLV
      @param[out] msg Messgae If it does not exist, a Null TLV is returned
      @return True if successful
      @note If multiple messages of the same type exist, return the first one
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefRead(m5::nfc::ndef::TLV& msg);
    /*!
      @brief Write NDEF message
      @param msg Messgae (NDEF Message)
      @return True if successful
      @note Other existing tags will be preserved
      @warning Existing NDEF message TLVs will be overwritten
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const m5::nfc::ndef::TLV& msg);
    ///@}

protected:
    bool dump_all();
    bool dump_block(const uint16_t block);

    bool detect_single(m5::nfc::v::PICC& picc);
    bool get_system_information(m5::nfc::v::PICC& picc);
    bool get_system_information_ext(m5::nfc::v::PICC& picc);
    bool read_block_ext(uint8_t rx[32], const m5::nfc::v::PICC& picc, const uint16_t block);
    bool write_block_ext(const m5::nfc::v::PICC& picc, const uint16_t block, const uint8_t* tx, const uint8_t tx_len);
    bool reset_to_ready(const m5::nfc::v::PICC* picc);
    bool stay_quiet(const m5::nfc::v::PICC& picc);

    virtual uint16_t first_user_block() const override
    {
        return _activePICC.firstUserBlock();
    }
    virtual uint16_t last_user_block() const override
    {
        return _activePICC.lastUserBlock();
    }
    inline virtual uint16_t user_area_size() const
    {
        return _activePICC.userAreaSize();
    }
    inline virtual uint16_t unit_size_read() const override
    {
        return _activePICC.block_size;
    }
    inline virtual uint16_t unit_size_write() const override
    {
        return _activePICC.block_size;
    }

protected:
    m5::nfc::v::PICC _activePICC{};

private:
    std::unique_ptr<Adapter> _impl;
    m5::nfc::ndef::NDEFLayer _ndef;
    m5::nfc::v::ModulationMode _modulation{m5::nfc::v::ModulationMode::OneOf4};
};

///@cond
// Impl for units
struct NFCLayerV::Adapter {
    virtual ~Adapter()                      = default;
    virtual uint16_t max_fifo_depth() const = 0;

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms, const m5::nfc::v::ModulationMode mode) = 0;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms,
                          const m5::nfc::v::ModulationMode mode)                              = 0;
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)            = 0;
};
///@endcond

}  // namespace nfc
}  // namespace m5
#endif
