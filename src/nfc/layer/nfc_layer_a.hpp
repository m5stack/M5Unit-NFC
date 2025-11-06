/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a.hpp
  @brief Common layer for NFC-A Related Units
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_A_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_A_HPP

#include "nfc/a/nfca.hpp"
#include <memory>
#include <vector>

namespace m5 {

namespace unit {
class UnitMFRC522;  // M5Unit-RFID
class UnitWS1850S;  // M5Unit-RFID
class UnitST25R3916;
class CapST25R3916;

namespace nfc {

class NFCLayerA {
public:
    struct Adapter;
    explicit NFCLayerA(UnitMFRC522& u);  //  The implementation of this function is located in M5Unit-RFID
    explicit NFCLayerA(UnitWS1850S& u);  // The implementation of this function is located in M5Unit-RFID
    explicit NFCLayerA(UnitST25R3916& u);
    explicit NFCLayerA(CapST25R3916& u);

    /*!
      @brief Is the specified UID active?
     */
    inline bool isActive(const m5::nfc::a::UID& uid) const
    {
        return _activeUID.valid() && _activeUID == uid;
    }
    /*!
      @brief Retrieve the activated UID
      @return UID
      @note Return empty UID if not exists
    */
    const m5::nfc::a::UID& activatedDevice() const
    {
        return _activeUID;
    }

    ///@name Detection and activation
    ///@{
    /*!
      @brief Request for IDLE PICC
      @param[out] atqa ATQA
      @return True if successful
      @note PICC to READY state
     */
    bool request(uint16_t& atqa);
    /*!
      @brief Wakeup for IDLE/HALT PICC
      @param[out] atqa ATQA
      @return True if successful
      @note PICC to READY state
     */
    bool wakeup(uint16_t& atqa);
    /*!
      @brief Detect idle devices
      @param[out] devices Detected devices
      @param timeout_ms Timeout (ms)
      @return True if successful
     */
    bool detect(std::vector<m5::nfc::a::UID>& devices, const uint32_t timeout_at = 10 * 1000U);
    /*!
      @brief Select for READY PICC
      @param[out] uid activated UID
      @return True if successful
      @note PICC to ACTIVE state
     */
    bool select(m5::nfc::a::UID& uid);
    /*!
      @brief Activate specific device
      @param uid UID
      @return True if successful
      @note PICC to ACTIVE
     */
    bool activate(const m5::nfc::a::UID& uid);
    ///@}

    ///@pre PICC activated
    ///@name For activated device
    ///@{
    /*!
      @brief Deactivate activated device
      @return True if successful
      @note PICCC to HALT
     */
    bool deactivate();
    /*!
      @brief Authentication by KeyA
      @param uid UID
      @param block Authentication block
      @param key MIFARE classic key
      @param encrypted Is it already in an encrypted state?
    */
    bool mifareClassicAuthenticateA(
        const m5::nfc::a::UID& uid, const uint8_t block,
        const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_CLASSIC_KEY);
    /*!
      @brief Authentication by KeyB
      @param uid UID
      @param block Authentication block
      @param key MIFARE classic key
      @param encrypted Is it already in an encrypted state?
    */
    bool mifareClassicAuthenticateB(
        const m5::nfc::a::UID& uid, const uint8_t block,
        const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_CLASSIC_KEY);
    /*!
      @brief Read the 1 block
      @param rx Buffer
      @param[in/out] in:Buffer length out:Actual read length
      @param addr Block address
      @warning The size per block varies by device
     */
    bool read(uint8_t* rx, uint16_t& rx_len, const uint16_t addr);
    /*!
      @brief Write the 1 block
      @param addr Block address
      @param tx Buffer
      @param tx_len :Buffer length out:Actual read length
      @param safety Fail to write to out of the user memory area if true (safety measure)
      @warning The size per block varies by device
      @note If the size exceeds the block size, truncate
      @note If it does not exceed the block size, pad with 0x00
     */
    bool write(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety = true);

    /*!
      @brief Dump all blocks for debug
      @param key MIFARE classic key
      @pre All blocks must be authenticatable using the specified key if MIFARE classic
     */
    bool dump(const m5::nfc::a::mifare::classic::Key& mkey = m5::nfc::a::mifare::classic::DEFAULT_CLASSIC_KEY);
    /*!
      @brief Dump 1 block
      @param addr Block address
      @note The sector to which the block belongs is dumped
      @pre The block must be authenticated if MIFARE classic
    */
    bool dump(const uint8_t block);
    ///@}

protected:
    m5::nfc::a::Type identify_type(const m5::nfc::a::UID& uid);

    bool nfca_transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                         const uint32_t timeout_ms);

    bool ntag_get_version(uint8_t info[10]);

    bool dump_sector_structure(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::classic::Key& key);
    bool dump_sector(const uint8_t sector);
    bool dump_page_structure(const uint8_t maxPage);
    bool dump_page(const uint8_t page);

protected:
    m5::nfc::a::UID _activeUID{};

    static bool push_back_uid(std::vector<m5::nfc::a::UID>& v, const m5::nfc::a::UID& uid);

private:
    std::unique_ptr<Adapter> _impl;
};

// Impl for units
struct NFCLayerA::Adapter {
    virtual ~Adapter() = default;

    virtual bool request(uint16_t& atqa) = 0;
    virtual bool wakeup(uint16_t& atqa)  = 0;

    virtual bool select(m5::nfc::a::UID& uid)         = 0;
    virtual bool activate(const m5::nfc::a::UID& uid) = 0;
    virtual bool deactivate()                         = 0;

    virtual bool nfca_transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                 const uint32_t timeout_ms)                                      = 0;
    virtual bool nfca_read_block(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)             = 0;
    virtual bool nfca_write_block(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len) = 0;

    virtual bool mifare_classic_authenticate(const bool auth_a, const m5::nfc::a::UID& uid, const uint8_t block,
                                             const m5::nfc::a::mifare::classic::Key& key)                  = 0;
    virtual bool mifare_classic_read_block(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)             = 0;
    virtual bool mifare_classic_write_block(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len) = 0;

    virtual bool ntag_get_version(uint8_t info[10]) = 0;

protected:
};

}  // namespace nfc
}  // namespace unit
}  // namespace m5

#endif
