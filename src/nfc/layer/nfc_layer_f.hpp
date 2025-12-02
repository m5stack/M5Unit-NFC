/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_f.hpp
  @brief Common layer for NFC-F related units

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: ISO14443-3 state names

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_F_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_F_HPP

#include "nfc/f/nfcf.hpp"
#include "ndef_layer.hpp"
#include <vector>
#include <memory>

namespace m5 {
namespace unit {
class UnitST25R3916;
class CapST25R3916;

namespace nfc {

/*!
  @class NFCLayerF
  @brief Common interface layer for each chip of the NFC-F reader
 */
class NFCLayerF : public m5::nfc::NFCLayerInterface {
public:
    struct Adapter;
    explicit NFCLayerF(UnitST25R3916& u);
    explicit NFCLayerF(CapST25R3916& u);

    /*!
      @brief Is the specified PICC currently active?
      @param picc PICC to check
      @return True if this PICC is the one currently selected (ACTIVE state)
    */
    inline bool isActive(const m5::nfc::f::PICC& picc) const
    {
        return _activePICC.valid() && _activePICC == picc;
    }
    /*!
      @brief Retrieve the currently activated PICC
      @return Active PICC
      @note Returns an empty PICC if no PICC is selected (no ACTIVE state)
    */
    const m5::nfc::f::PICC& activatedPICC() const
    {
        return _activePICC;
    }

    ///@name Detection and activation
    ///@{
    /*!
      @brief Polling
      @param[out] PICC detected PICC
      @param system_code System code
      @param request_code Request code
      @param time_slot Maximum number of slots that can be responded
      @return True if successful
      @note SENSF_REQ
     */
    bool polling(m5::nfc::f::PICC& picc, const uint16_t system_code, const m5::nfc::f::RequestCode request_code,
                 const m5::nfc::f::TimeSlot time_slot);

    /*!
      @brief Detect single PICC
      @param[out] picc Detected PICC
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @warning Misclassification may occur depending on the distance between the reader and the PICC
     */
    bool detect(m5::nfc::f::PICC& picc, const uint32_t timeout_ms = 25);
    /*!
      @brief Detect PICCs
      @param[out] piccs Detected PICCs
      @param time_slot Maximum number of slots that can be responded
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @warning Misclassification may occur depending on the distance between the reader and the PICC
     */
    inline bool detect(std::vector<m5::nfc::f::PICC>& piccs,
                       m5::nfc::f::TimeSlot time_slot = m5::nfc::f::TimeSlot::Slot16, const uint32_t timeout_ms = 500U)
    {
        return detect(piccs, nullptr, 0, time_slot, timeout_ms);
    }
    /*!
      @brief Detect PICCs matching the specified system code
      @param[out] piccs Detected PICCs
      @param private_code Private system code
      @param time_slot Maximum number of slots that can be responded
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note If a private code is specified, PICC that does not meet the conditions will not be detected
      @warning Misclassification may occur depending on the distance between the reader and the PICC
     */
    inline bool detect(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t private_code,
                       m5::nfc::f::TimeSlot time_slot = m5::nfc::f::TimeSlot::Slot16, const uint32_t timeout_ms = 500U)
    {
        return detect(piccs, &private_code, 1, time_slot, timeout_ms);
    }
    /*!
      @brief Detect PICCs matching the specified system code
      @param[out] piccs Detected PICCs
      @param private_code Private system code array
      @param pc_size private_code size
      @param time_slot Maximum number of slots that can be responded
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note If a private code is specified, PICC that does not meet the conditions will not be detected
      @note private codes are OR matching
      @warning Misclassification may occur depending on the distance between the reader and the PICC
     */
    bool detect(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t* private_code, const uint8_t pc_size,
                m5::nfc::f::TimeSlot time_slot = m5::nfc::f::TimeSlot::Slot16, const uint32_t timeout_ms = 500U);

    /*!
      @brief Activate a specific PICC
      @param picc PICC
      @return True if successful
     */
    bool activate(const m5::nfc::f::PICC& picc);
    /*!
      @brief Activate a specific PICC
      @param picc PICC
      @return True if successful
      @note For compatibility with other NFCLayer components
     */
    inline bool reactivate(const m5::nfc::f::PICC& picc)
    {
        return activate(picc);
    }
    ///@}

    ///@name For activated PICC
    ///@{
    /*!
      @brief Deactivate PICC
      @return True if successful
     */
    bool deactivate();

    /*!
      @brief Read the 1 block
      @param[out] rx Output buffer
      @param block Target block
      @return True if successful
      @note Using readWithoutEncryption
     */
    inline bool read16(uint8_t rx[16], const m5::nfc::f::block_t block)
    {
        return read_16(rx, block, true);
    }
    /*!
      @brief Read any bytes from user area
      @details Continue reading only the user area from the first block of the user area until rx_len is satisfied
      @param[out] rx Buffer
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param sblock Block to start reading
      @return True if successful
      @note Using readWithoutEncryption
      @warning rx in 16-byte units
    */
    bool read(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::block_t sblock);

    /*!
      @brief Write the 1 block
      @param block Target block
      @param tx Buffer
      @param tx_len Buffer size
      @return True if successful
      @note Using writeWithoutEncryption
      @warning If the tx_len is less than 16 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 16 bytes, only the first 16 bytes will be written
     */
    bool write16(const m5::nfc::f::block_t block, const uint8_t tx[16], const uint16_t tx_len);
    /*!
      @brief Write any bytes to user area
      @details Continue writing only the user area from the first block of the user area until tx_len is satisfied
      @param sblock Block to start writing
      @param tx Buffer
      @param tx_len Buffer size
      @return True if successful
      @note Using writeWithoutEncryption
    */
    bool write(const m5::nfc::f::block_t sblock, const uint8_t* tx, const uint16_t tx_len);
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
      @brief Read NDEF Message TLV
      @param[out] msg Messgae If it does not exist, a Null TLV is returned
      @return True if successful
      @note If multiple messages of the same type exist, return the first one
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefRead(m5::nfc::ndef::TLV& msg);
    /*!
      @brief Read any NDEF TLV
      @param[out] msgs Messgae vector
      @param tagBits Bit indicating the group of NDEF tags to be read
      @return True if successful
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefRead(std::vector<m5::nfc::ndef::TLV>& tlvs,
                  const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsAll);
    /*!
      @brief Write NDEF message
      @param msg Messgae (NDEF Message)
      @return True if successful
      @note Other existing tags will be preserved
      @warning Existing NDEF message TLVs will be overwritten
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const m5::nfc::ndef::TLV& msg);
    /*!
      @brief Write any NDEF Messages TLV
      @param msgs Messgae vector
      @return True if successful
      @note Write starting from the beginning of the user area
      @warning Existing NDEF Message TLVs will be overwritten,
      @warning so exercise caution if Lock/Memory control is present
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const std::vector<m5::nfc::ndef::TLV>& tlvs);

    /*!
      @brief Write changes for NDEF Support
      @param enabled Support NDEF if true, NOT support NDEF if false
      @return True if successful
      @warning Only FeliCa Lite, Lite-S
    */
    bool writeSupportNDEF(const bool enabled);
    ///@}

    bool requestService(uint16_t& key_version, const uint16_t node_code);
    bool requestService(uint16_t key_version[], const uint16_t* node_code, const uint8_t node_num);

    ///@note For activated PICC
    ///@note Dump
    ///@{

    /*!
      @brief Dump all blocks
      @return True if successful
      @note Only the sections that can be read without authentication
     */
    bool dump();
    /*!
      @brief Dump 1 block
      @param block block list element
      @return True if successful
      @note Only the sections that can be read without authentication
    */
    bool dump(const m5::nfc::f::block_t block);
    ///@}

protected:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr) override;
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) override;
    virtual uint16_t firstUserBlock() const override;
    virtual uint16_t lastUserBlock() const override;
    inline virtual uint16_t userBlockUnitSize() const override
    {
        return 16u;
    }
    virtual uint8_t maximumReadBlocks() const override;
    virtual uint8_t maximumWriteBlocks() const override;

    bool read_16(uint8_t rx[16], const m5::nfc::f::block_t block, const bool check_valid);

    bool dump_felica_lite();
    bool dump_felica_lite_s();
    bool dump_block(m5::nfc::f::block_t block);

protected:
    m5::nfc::f::PICC _activePICC{};

private:
    std::unique_ptr<Adapter> _impl;
    m5::nfc::ndef::NDEFLayer _ndef;
};

///@cond
// Impl for units
struct NFCLayerF::Adapter {
    virtual ~Adapter() = default;

    virtual bool polling(m5::nfc::f::PICC& picc, const uint16_t system_code, const m5::nfc::f::RequestCode request_code,
                         const m5::nfc::f::TimeSlot time_slot)                                             = 0;
    virtual bool requestService(uint16_t key_version[], const m5::nfc::f::PICC& picc, const uint16_t* node_code,
                                const uint8_t node_num)                                                    = 0;
    virtual bool readWithoutEncryption(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::PICC& picc,
                                       const uint16_t* service_code, const uint8_t service_num,
                                       const m5::nfc::f::block_t* block_list, const uint8_t block_num)     = 0;
    virtual bool writeWithoutEncryption(const m5::nfc::f::PICC& picc, const uint16_t* service_code,
                                        const uint8_t service_num, const m5::nfc::f::block_t* block_list,
                                        const uint8_t block_num, const uint8_t* tx, const uint16_t tx_len) = 0;
};
///@endcond

}  // namespace nfc
}  // namespace unit
}  // namespace m5
#endif
