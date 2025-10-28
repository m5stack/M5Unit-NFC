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

    inline bool isActive(const m5::nfc::a::UID& uid) const
    {
        return uid.valid() && activatedDevice() == uid;
    }

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

    ///@name For activated device
    ///@{
    /*!
      @brief Deactivate specific device
      @return True if successful
      @note PICC to HALT
     */
    bool deactivate();
    /*!
      @brief Authentication by KeyB
    */
    inline bool mifareAuthenticateA(const m5::nfc::a::UID& uid, const uint8_t block,
                                    const m5::nfc::a::mifare::Key& key = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY)
    {
        return mifare_authenticate(m5::nfc::a::Command::AUTH_WITH_KEY_A, uid, block, key);
    }
    /*!
      @brief Authentication by KeyB
    */
    inline bool mifareAuthenticateB(const m5::nfc::a::UID& uid, const uint8_t block,
                                    const m5::nfc::a::mifare::Key& key = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY)
    {
        return mifare_authenticate(m5::nfc::a::Command::AUTH_WITH_KEY_B, uid, block, key);
    }

    bool read(uint8_t* rx, uint16_t& tx_len, const uint16_t addr);
    //    bool write(uint16_t& actual, const uint16_t offset, const uint8_t* buf, const uint16_t len);
    bool dump(const m5::nfc::a::UID& uid,
              const m5::nfc::a::mifare::Key& mkey = m5::nfc::a::mifare::DEFAULT_CLASSIC_KEY);
    ///@}

protected:
    bool mifare_authenticate(const m5::nfc::a::Command cmd, const m5::nfc::a::UID& uid, const uint8_t block,
                             const m5::nfc::a::mifare::Key& key);
    bool dump_sector_structure(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::Key& key);
    bool dump_sector(const uint8_t sector);

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
    virtual bool detect(std::vector<m5::nfc::a::UID>&, const uint32_t)   = 0;
    virtual bool activate(const m5::nfc::a::UID& uid)                    = 0;
    virtual bool deactivate()                                            = 0;
    virtual bool mifare_authenticate(const m5::nfc::a::Command cmd, const m5::nfc::a::UID& uid, const uint8_t block,
                                     const m5::nfc::a::mifare::Key& key) = 0;

    virtual bool read(uint8_t* rx, uint16_t& tx_len, const uint16_t addr) = 0;
    //    virtual bool write(const uint16_t offset, const uint8_t* tx, const uint16_t tx_len)            = 0;

protected:
    m5::nfc::a::UID _activeUID{};
};

}  // namespace nfc
}  // namespace unit
}  // namespace m5

#endif
