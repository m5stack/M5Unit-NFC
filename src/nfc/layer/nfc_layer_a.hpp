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
      @brief Read the 1 block / 4 page (16 bytes)
      @param rx Buffer (at least 16 bytes)
      @param addr Block/Page address
      @return True if successful
      @pre The block must be authenticated if MIFARE classic
     */
    bool read16(uint8_t rx[16], const uint8_t addr);
    /*!
      @brief Write the 1 block / 4 page (16 bytes)
      @param addr Block/Page address
      @param tx Buffef
      @param tx_len Buffer size
      @param safety Fail to write to out of the user memory area if true (safety measure)
      @return True if successful
      @warning If the tx_len is less than 16 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 16 bytes, only the first 16 bytes will be written
      @pre The block must be authenticated if MIFARE classic
    */
    bool write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len = 16, const bool safety = true);
    /*!
      @brief Read the 1 page
      @param rx Buffer (at least 4 bytes)
      @param addr Block/Page address
      @return True if successful
      @warning Only PICC supporting the FAST_READ command is possible
     */
    bool read4(uint8_t rx[4], const uint8_t addr);
    /*!
      @brief Write the 1 page (4 bytes)
      @param addr Block/Page address
      @param tx Buffer
      @param tx_len Buffer size
      @param safety Fail to write to out of the user memory area if true (safety measure)
      @return True if successful
      @warning Supports NTAG and UltraLight only
      @warning If the tx_len is less than 4 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 4 bytes, only the first 4 bytes will be written
     */
    bool write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len = 4, const bool safety = true);
    /*!
      @brief Read any bytes from user area
      @details Continue reading only the user area from the first block of the user area until rx_len is satisfied
      @param rx Buffer
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param saddr Reading start block/page address
      @return True if successful
      @warning For FAST_READ-compatible devices, the rx is in 4-byte units. for others, it is in 16-byte units
      @pre Target blocks must be authenticatable using the specified key if MIFARE classic
    */
    bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr,
              const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Write any bytes to user area
      @details Continue writing only the user area from the first block of the user area until tx_len is satisfied
      @param saddr Writing start block/page address
      @param tx Buffer
      @param tx_len buffer size
      @return True if successful
      @warning For NTAG and UltraLight, the tx is in 4-byte units; for others, it is in 16-byte units
      @warning If the value is less than the unit, it is padded with 0x00
      @pre Target blocks must be authenticatable using the specified key if MIFARE classic
    */
    bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len,
               const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);

    /*!
      @brief Authentication by KeyA for MIFARE classsic
      @param uid UID
      @param block Authentication block
      @param key MIFARE classic key
      @param encrypted Is it already in an encrypted state?
    */
    bool mifareClassicAuthenticateA(
        const m5::nfc::a::UID& uid, const uint8_t block,
        const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Authentication by KeyB for MIFARE classic
      @param uid UID
      @param block Authentication block
      @param key MIFARE classic key
      @param encrypted Is it already in an encrypted state?
    */
    bool mifareClassicAuthenticateB(
        const m5::nfc::a::UID& uid, const uint8_t block,
        const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);

    /*!
      @brief Dump all blocks for debug
      @param key MIFARE classic key
      @pre All blocks must be authenticatable using the specified key if MIFARE classic
     */
    bool dump(const m5::nfc::a::mifare::classic::Key& mkey = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Dump 1 block
      @param addr Block address
      @note The sector to which the block belongs is dumped
      @pre The block must be authenticated if MIFARE classic
    */
    bool dump(const uint8_t block);
    ///@}

protected:
    bool read_using_fast(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr);
    bool read_using_read16(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr,
                           const m5::nfc::a::mifare::classic::Key& key);
    bool write_using_write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len);
    bool write_using_write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                             const m5::nfc::a::mifare::classic::Key& key);

    bool dump_sector_structure(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::classic::Key& key);
    bool dump_sector(const uint8_t sector);
    bool dump_page_structure(const uint16_t maxPage);
    bool dump_page(const uint8_t page, const uint16_t maxPage);

    static bool push_back_uid(std::vector<m5::nfc::a::UID>& v, const m5::nfc::a::UID& uid);

protected:
    m5::nfc::a::UID _activeUID{};

private:
    std::unique_ptr<Adapter> _impl;
};

// Impl for units
struct NFCLayerA::Adapter {
    virtual ~Adapter() = default;

    virtual uint16_t max_fifo_depth() = 0;

    virtual bool request(uint16_t& atqa) = 0;
    virtual bool wakeup(uint16_t& atqa)  = 0;

    virtual bool select(m5::nfc::a::UID& uid)         = 0;
    virtual bool activate(const m5::nfc::a::UID& uid) = 0;
    virtual bool deactivate()                         = 0;

    virtual bool nfca_read_block(uint8_t rx[16], const uint8_t addr)        = 0;  // READ
    virtual bool nfca_write_block(const uint8_t addr, const uint8_t tx[16]) = 0;  // WRITE_BLOCK
    virtual bool nfca_write_page(const uint8_t addr, const uint8_t tx[4])   = 0;  // WRITE_PAGE

    virtual bool mifare_classic_authenticate(const bool auth_a, const m5::nfc::a::UID& uid, const uint8_t block,
                                             const m5::nfc::a::mifare::classic::Key& key) = 0;

    virtual bool ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage,
                                const uint8_t epage) = 0;  // FAST_READ

    //    virtual bool mifare_classic_read_block(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)             = 0;
    //    virtual bool mifare_classic_write_block(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len) = 0;

protected:
};

}  // namespace nfc
}  // namespace unit
}  // namespace m5

#endif
