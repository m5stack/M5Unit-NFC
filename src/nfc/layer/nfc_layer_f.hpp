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

    ///@name Detection
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
     */
    inline bool detect(m5::nfc::f::PICC& picc, const uint32_t timeout_ms)
    {
        return detect(picc, 0xFFFF /*skip*/, timeout_ms);
    }
    /*!
      @brief Detect single PICC matching the specified system code
      @param[out] picc Detected PICC
      @param system_code System code
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
     */
    bool detect(m5::nfc::f::PICC& picc, const uint16_t system_code, const uint32_t timeout_ms = 100U);
    /*!
      @brief Detect PICCs
      @param[out] piccs Detected PICCs
      @param time_slot Maximum number of slots that can be responded
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
     */
    inline bool detect(std::vector<m5::nfc::f::PICC>& piccs,
                       m5::nfc::f::TimeSlot time_slot = m5::nfc::f::TimeSlot::Slot16, const uint32_t timeout_ms = 500U)
    {
        return detect_picc(piccs, nullptr, 0, time_slot, timeout_ms);
    }
    /*!
      @brief Detect PICCs matching the specified system code
      @param[out] piccs Detected PICCs
      @param system_code System code
      @param time_slot Maximum number of slots that can be responded
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
     */
    bool detect(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t system_code,
                m5::nfc::f::TimeSlot time_slot = m5::nfc::f::TimeSlot::Slot16, const uint32_t timeout_ms = 500U);

protected:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr) override;
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) override;
    virtual uint16_t firstUserBlock() const override;
    virtual uint16_t lastUserBlock() const override;

    bool detect_picc(std::vector<m5::nfc::f::PICC>& piccs, const uint16_t* private_system_code, const uint8_t pc_size,
                     m5::nfc::f::TimeSlot time_slot, const uint32_t timeout_ms);

private:
    std::unique_ptr<Adapter> _impl;
    m5::nfc::ndef::NDEFLayer _ndef;
};

///@cond
// Impl for units
struct NFCLayerF::Adapter {
    virtual ~Adapter() = default;

    virtual bool polling(m5::nfc::f::PICC& picc, const uint16_t system_code, const m5::nfc::f::RequestCode request_code,
                         const m5::nfc::f::TimeSlot time_slot) = 0;
};
///@endcond

}  // namespace nfc
}  // namespace unit
}  // namespace m5
#endif
