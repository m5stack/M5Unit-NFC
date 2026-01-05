/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_f.hpp
  @brief Common layer for NFC-F

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_F_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_F_HPP

#include "nfc_layer.hpp"
#include "nfc/f/nfcf.hpp"
#include "ndef_layer.hpp"
#include <vector>
#include <memory>

namespace m5 {
namespace unit {
class UnitST25R3916;
class CapST25R3916;
}  // namespace unit

namespace nfc {

/*!
  @class NFCLayerF
  @brief Common interface layer for each chip of the NFC-F reader
 */
class NFCLayerF : public NFCLayerInterface {
public:
    struct Adapter;
    explicit NFCLayerF(m5::unit::UnitST25R3916& u);
    explicit NFCLayerF(m5::unit::CapST25R3916& u);

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
    bool detect(m5::nfc::f::PICC& picc, const uint32_t timeout_ms = 100U);
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
      @note For compatibility with other NFCLayer components
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
      @note For compatibility with other NFCLayer components
     */
    bool deactivate();

    /*!
      @brief Request service
      @param[out] key_version Key version
      @param node_code Node code
      @return True if successful
      @warning FeliCa Standard only
     */
    bool requestService(uint16_t& key_version, const uint16_t node_code);
    /*!
      @brief Request service
      @param[out] key_version Key version array (at leaset node_num)
      @param node_code Node code array
      @param node_num Number of node_code
      @return True if successful
      @warning FeliCa Standard only
     */
    bool requestService(uint16_t key_version[], const uint16_t* node_code, const uint8_t node_num);

    /*!
      @brief Request response
      @return True if successful
      @param[out] mode Mode if detected
      @warning FeliCa Standard only
     */
    inline bool requestResponse(m5::nfc::f::standard::Mode& mode)
    {
        return _activePICC.valid() && request_response_impl(_activePICC, mode);
    }

    /*!
      @brief Request system code
      @param[out] code_list Code list array (at least 255)
      @param[out] code_num Number of code_list
      @return True if successful
      @warning FeliCa Standard only
     */
    bool requestSystemCode(uint16_t code_list[255], uint8_t& code_num);

    /*!
      @brief Dump all blocks
      @return True if successful
      @note Only the sections that can be read without encryption
     */
    bool dump();
    /*!
      @brief Dump 1 block
      @param block block list element
      @return True if successful
      @note Only the sections that can be read without encryption
    */
    bool dump(const m5::nfc::f::block_t block);
    ///@}

    ///@note For activated PICC
    ///@name Read/Write without encryption
    /*!
      @brief Read the 1 block with service code
      @param[out] rx Output buffer
      @param block Target block
      @param service_code Service code
      @return True if successful
     */
    inline bool read16(uint8_t rx[16], const m5::nfc::f::block_t block,
                       const uint16_t service_code = m5::nfc::f::service_random_read)
    {
        return read16(rx, &block, 1, service_code);
    }
    /*!
      @brief Read the 1 block with service codes
      @param[out] rx Output buffer
      @param block Target block array
      @param block_num Number of block
      @param service_code Service code
      @return True if successful
      @param service_code Service code
     */
    bool read16(uint8_t rx[16], const m5::nfc::f::block_t* block, const uint8_t block_num,
                const uint16_t service_code = m5::nfc::f::service_random_read);

    /*!
      @brief Read any bytes from user area
      @details Continue reading only the user area from the first block of the user area until rx_len is satisfied
      @param[out] rx Buffer
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param sblock Block to start reading
      @return True if successful
      @warning rx in 16-byte units
    */
    bool read(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::block_t sblock);

    /*!
      @breif Read the specified block list and service codes
      @param[out] rx Buffer (At least 16 * block_num)
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param block Target block array
      @param block_num Number of block
      @param service_code Service code array
      @param service_num Number of service code
      @return True if successful
      @warning rx in 16-byte units
     */
    inline bool read(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::block_t* block_list, const uint8_t block_num,
                     const uint16_t* service_code, const uint8_t service_num)
    {
        return _activePICC.valid() &&
               read_without_encryption_impl(rx, rx_len, block_list, block_num, service_code, service_num, _activePICC);
    }

    /*!
      @brief Write the 1 block
      @param block Target block
      @param tx Buffer
      @param tx_len Buffer size
      @return True if successful
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
    */
    bool write(const m5::nfc::f::block_t sblock, const uint8_t* tx, const uint16_t tx_len);

    /*!
      @brief Clear SPAD_0 - 13
      @return True if successful
      @pre Each area can be written to without authentication
    */
    bool clearSPAD();

    ///@}

    ///@note For activated PICC
    ///@name Read/Write with MAC
    ///@{
    /*!
      @brief Internal authentication
      @param ck Card key
      @param ckv Card key version
      @param rc Random challenge
      @return True if successful
     */
    bool internalAuthenticate(const uint8_t ck[16], const uint16_t ckv, const uint8_t rc[16]);
    /*!
      @brief External authentication
      @param wcnt WCNT value
      @return True if successful
      @pre internalAuthenticate
     */
    bool externalAuthenticate(const uint8_t ck[16], const uint16_t ckv);

    void clearAuthenticate()
    {
        _authenticated = false;
    }

    /*!
      @brief Read the 1 block
      @param[out] rx Output buffer
      @param block Target block
      @return True if successful
      @pre internalAuthentication
     */
    bool readWithMAC16(uint8_t rx[16], const m5::nfc::f::block_t block);

    /*!
      @brief Write the 1 block
      @param block Target block
      @param tx Buffer
      @param tx_len Buffer size
      @return True if successful
      @warning If the tx_len is less than 16 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 16 bytes, only the first 16 bytes will be written
     */
    bool writeWithMAC16(const m5::nfc::f::block_t block, const uint8_t tx[16], const uint16_t tx_len);
    ///@}

    ///@note For activated PICC
    ///@name NDEF
    ///@{
    /*!
      @brief Is the PICC data in NDEF format?
[      @param[out] valid True if NDEF format
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
      @brief Write NDEF message TLV
      @param msg Messgae TLV
      @return True if successful
      @warning Existing record will be overwritten
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const m5::nfc::ndef::TLV& msg);

    /*!
      @brief Write changes for NDEF Support
      @param enabled Support NDEF if true, NOT support NDEF if false
      @return True if successful
      @warning Only FeliCa Lite, Lite-S
    */
    bool writeSupportNDEF(const bool enabled);
    ///@}

protected:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr) override;
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) override;
    inline virtual uint16_t first_user_block() const override
    {
        return _activePICC.firstUserBlock();
    }
    inline virtual uint16_t last_user_block() const override
    {
        return _activePICC.lastUserBlock();
    }
    inline virtual uint16_t user_area_size() const
    {
        return _activePICC.userAreaSize();
    }
    inline virtual uint16_t unit_size_read() const override
    {
        return 16;
    }
    inline virtual uint16_t unit_size_write() const override
    {
        return 16;
    }
    inline virtual uint8_t maximum_read_blocks() const override
    {
        return _activePICC.maximumReadBlocks();
    }
    inline virtual uint8_t maximum_write_blocks() const override
    {
        return _activePICC.maximumWriteBlocks();
    }

    bool request_response_impl(const m5::nfc::f::PICC& picc, m5::nfc::f::standard::Mode& mode);
    bool read_without_encryption_impl(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::block_t* block_list,
                                      const uint8_t block_num, const uint16_t* service_code, const uint8_t service_num,
                                      const m5::nfc::f::PICC& picc);
    bool write_without_encryption_impl(const m5::nfc::f::PICC& picc, const m5::nfc::f::block_t* block_list,
                                       const uint8_t block_num, const uint16_t* service_code, const uint8_t service_num,
                                       const uint8_t* tx, const uint16_t tx_len);

    bool dump_felica_lite();
    bool dump_felica_lite_s();
    bool dump_block(m5::nfc::f::block_t block);

    bool internal_authenticate_lite_s(const uint8_t ck[16], const uint16_t ckv, const uint8_t rc[16],
                                      const bool include_wcnt = false);
    bool external_authenticate_lite_s(const uint8_t ck[16], const uint16_t ckv);

protected:
    m5::nfc::f::PICC _activePICC{};

private:
    std::unique_ptr<Adapter> _impl;
    m5::nfc::ndef::NDEFLayer _ndef;
    union {
        uint8_t _sk[16]{};
        struct {
            uint8_t _sk1[8];
            uint8_t _sk2[8];
        };
    };
    uint8_t _rc[16]{};
    bool _authenticated{};
};

///@cond
// Impl for units
struct NFCLayerF::Adapter {
    virtual ~Adapter() = default;

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) = 0;
};
///@endcond

}  // namespace nfc
}  // namespace m5
#endif
