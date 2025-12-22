/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_a.hpp
  @brief Emulation layer for NFC-A

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: ISO14443-3 state names

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_A_EMULATION_LAYER_A_HPP
#define M5_UNIT_NFC_NFC_LAYER_A_EMULATION_LAYER_A_HPP

#include "nfc/a/nfca.hpp"
// #include "nfc/layer/ndef_layer.hpp"
#include <vector>
#include <memory>

namespace m5 {

namespace unit {
class UnitST25R3916;
class CapST25R3916;
}  // namespace unit

namespace nfc {

/*!
  @class EmulationLayerA
  @brief Common interface layer for each chip of the NFC-A emulation
 */
class EmulationLayerA {
public:
    enum class State { None, Off, Idle, Ready, Active, Halt };

    struct Adapter;
    explicit EmulationLayerA(m5::unit::UnitST25R3916& u);
    explicit EmulationLayerA(m5::unit::CapST25R3916& u);

    inline State state() const
    {
        return _state;
    }
    inline const m5::nfc::a::PICC& emulatePICC() const
    {
        return _picc;
    }
    inline uint32_t expiredTime() const
    {
        return _expired_ms;
    }
    void setExpiredTime(const uint32_t ms)
    {
        _expired_ms = ms;
    }

    bool begin(const m5::nfc::a::PICC& picc, uint8_t* ptr, const uint32_t size);
    bool end();
    void update();

    virtual State receive_callback(const uint8_t* rx, const uint32_t rx_len);

protected:
    void update_expired();

private:
    void update_off();
    void update_idle();
    void update_ready();
    void update_active();
    void update_halt();

protected:
    uint8_t* _memory{};
    uint32_t _memory_size{};

private:
    State _state{}, _prev{};
    uint32_t _expired_ms{60 * 1000u};
    unsigned int _expired_at{};
    std::unique_ptr<Adapter> _impl;
    m5::nfc::a::PICC _picc{};
};

///@cond
// Impl for units
struct EmulationLayerA::Adapter {
    virtual ~Adapter() = default;

    virtual bool start_emulation(const m5::nfc::a::PICC& picc)                                 = 0;
    virtual bool stop_emulation()                                                              = 0;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) = 0;

    virtual EmulationLayerA::State update_off()    = 0;
    virtual EmulationLayerA::State update_idle()   = 0;
    virtual EmulationLayerA::State update_ready()  = 0;
    virtual EmulationLayerA::State update_active() = 0;
    virtual EmulationLayerA::State update_halt()   = 0;
};
///@endcond

}  // namespace nfc
}  // namespace m5
#endif
