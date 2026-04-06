/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_f.hpp
  @brief Emulation layer for NFC-F

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: ISO14443-3 state names

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_F_EMULATION_LAYER_F_HPP
#define M5_UNIT_NFC_NFC_LAYER_F_EMULATION_LAYER_F_HPP

#include "nfc/f/nfcf.hpp"
#include <vector>
#include <memory>

namespace m5 {

namespace unit {
class UnitST25R3916;
class CapST25R3916;
}  // namespace unit

namespace nfc {

/*!
  @class EmulationLayerF
  @brief Common interface layer for each chip of the NFC-F emulation
 */
class EmulationLayerF {
public:
    /*!
      @enum State
      @brief Emulation state for NFC-F
     */
    enum class State { None, Off, Communicated, Selected };

    struct Adapter;
    //! @brief Construct with UnitST25R3916 (I2C)
    explicit EmulationLayerF(m5::unit::UnitST25R3916& u);
    //! @brief Construct with CapST25R3916 (SPI)
    explicit EmulationLayerF(m5::unit::CapST25R3916& u);

    //! @brief Gets the current emulation state
    inline State state() const
    {
        return _state;
    }
    //! @brief Gets the emulated PICC information
    inline const m5::nfc::f::PICC& emulatePICC() const
    {
        return _picc;
    }
    //! @brief Gets the expiration time (ms)
    inline uint32_t expiredTime() const
    {
        return _expired_ms;
    }
    //! @brief Sets the expiration time (ms)
    void setExpiredTime(const uint32_t ms)
    {
        _expired_ms = ms;
    }

    //! @brief Begin NFC-F emulation
    bool begin(const m5::nfc::f::PICC& picc, uint8_t* ptr, const uint32_t size);
    //! @brief End NFC-F emulation
    bool end();
    //! @brief Update emulation state machine
    void update();

    virtual State receive_callback(const State s, const uint8_t* rx, const uint32_t rx_len);

protected:
    void update_expired();

private:
    void update_off();
    void update_communicated();
    void update_selected();

protected:
    uint8_t* _memory{};
    uint32_t _memory_size{};

private:
    State _state{}, _prev{};
    uint32_t _expired_ms{60 * 1000u};
    unsigned int _expired_at{};
    std::unique_ptr<Adapter> _impl;
    m5::nfc::f::PICC _picc{};
};

///@cond
// Impl for units
struct EmulationLayerF::Adapter {
    virtual ~Adapter() = default;

    virtual bool start_emulation(const m5::nfc::f::PICC& picc)                                 = 0;
    virtual bool stop_emulation()                                                              = 0;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) = 0;

    virtual EmulationLayerF::State update_off()          = 0;
    virtual EmulationLayerF::State update_communicated() = 0;
    virtual EmulationLayerF::State update_selected()     = 0;
};
///@endcond

}  // namespace nfc
}  // namespace m5
#endif
