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
        return uid.valid() && activatedDevice() == uid;
    }
    /*!
      @brief Retrieve the activated UID
      @return UID
      @note Return empty UID if not exists
    */
    const m5::nfc::a::UID& activatedDevice() const;

    ///@name Detection and activation
    ///@{
    /*!
      @brief Detect idle devices
      @param[out] devices Detected devices
      @param timeout_ms Timeout (ms)
      @return True if successful
     */
    bool detect(std::vector<m5::nfc::a::UID>& devices, const uint32_t timeout_at = 10 * 1000U);
    /*!
      @brief Activate specific device
      @param uid UID
      @return True if successful
      @note PICC to ACTIVE
     */
    bool activate(const m5::nfc::a::UID& uid);
    ///@}

    ///@pre UID activated
    ///@name For activated device
    ///@{
    /*!
      @brief Deactivate specific device
      @return True if successful
      @note PICC to HALT
     */
    bool deactivate();
    /*!
      @brief Authentication by KeyA
      @param uid UID
      @param block Authentication block
      @param key Mifare classic key
      @param encrypted Is it already in an encrypted state?
    */
    inline bool mifareAuthenticateA(const m5::nfc::a::UID& uid, const uint8_t block,
                                    const m5::nfc::a::mifare::Key& key = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY,
                                    const bool encrypted               = false)
    {
        return mifare_authenticate(m5::nfc::a::Command::AUTH_WITH_KEY_A, uid, block, key, encrypted);
    }
    /*!
      @brief Authentication by KeyB
      @param uid UID
      @param block Authentication block
      @param key Mifare classic key
      @param encrypted Is it already in an encrypted state?
    */
    inline bool mifareAuthenticateB(const m5::nfc::a::UID& uid, const uint8_t block,
                                    const m5::nfc::a::mifare::Key& key = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY,
                                    const bool encrypted               = false)
    {
        return mifare_authenticate(m5::nfc::a::Command::AUTH_WITH_KEY_B, uid, block, key, encrypted);
    }
    /*!
      @brief Read the 1 block
      @param rx Buffer
      @param[in/out] in:Buffer length out:Actual read length
      @param addr Block address
      @warning The size per block varies by device
     */
    bool readBlock(uint8_t* rx, uint16_t& rx_len, const uint16_t addr);
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
    bool writeBlock(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety = true);

    /*!
      @brief Dump all blocks for debug
      @param uid UID
      @param key Mifare classic key
      @wrning All blocks must be authenticatable using the specified key
     */
    bool dump(const m5::nfc::a::UID& uid,
              const m5::nfc::a::mifare::Key& mkey = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY);
    /*!
      @brief Dump 1 block
      @param uid UID
      @param addr Block address
      @note In Classic Mode, the specified block must have successfully authenticated
      @note The sector to which the block belongs is dumped
     */
    bool dump(const m5::nfc::a::UID& uid, const uint8_t block);
    ///@}

protected:
    bool mifare_authenticate(const m5::nfc::a::Command cmd, const m5::nfc::a::UID& uid, const uint8_t block,
                             const m5::nfc::a::mifare::Key& key, const bool encrypted);
    bool dump_sector_structure(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::Key& key);
    bool dump_sector(const uint8_t sector);
    bool dump_page_structure(const uint8_t maxPage);
    bool dump_page(const uint8_t page);

private:
    std::unique_ptr<Adapter> _impl;
};

// Impl for units
struct NFCLayerA::Adapter {
    virtual ~Adapter() = default;
    inline const m5::nfc::a::UID& activatedDevice() const
    {
        return _activeUID;
    }
    virtual bool detect(std::vector<m5::nfc::a::UID>&, const uint32_t) = 0;
    virtual bool activate(const m5::nfc::a::UID& uid)                  = 0;
    virtual bool deactivate()                                          = 0;

    virtual bool mifare_authenticate(const m5::nfc::a::Command cmd, const m5::nfc::a::UID& uid, const uint8_t block,
                                     const m5::nfc::a::mifare::Key& key, const bool encrypted) = 0;

    virtual bool readBlock(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)             = 0;
    virtual bool writeBlock(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len) = 0;

protected:
    static bool push_back_uid(std::vector<m5::nfc::a::UID>& v, const m5::nfc::a::UID& uid);

    m5::nfc::a::UID _activeUID{};
};

}  // namespace nfc
}  // namespace unit
}  // namespace m5

#endif
