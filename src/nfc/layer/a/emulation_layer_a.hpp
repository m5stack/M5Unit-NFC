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
#include <m5_utility/compatibility_feature.hpp>
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
  @note The chip emulates one technology at a time, so this cannot run alongside EmulationLayerF.
  The unit must be configured for NFC-A emulation before begin().
 */
class EmulationLayerA {
public:
    /*!
      @enum State
      @brief Emulation state for NFC-A
     */
    enum class State { None, Off, Idle, Ready, Active, Halt };

    struct Adapter;
    //! @brief Construct with UnitST25R3916 (I2C)
    explicit EmulationLayerA(m5::unit::UnitST25R3916& u);
    //! @brief Construct with CapST25R3916 (SPI)
    explicit EmulationLayerA(m5::unit::CapST25R3916& u);
    virtual ~EmulationLayerA();

    //! @brief Gets the current emulation state
    inline State state() const
    {
        return _state;
    }
    //! @brief Gets the emulated PICC information
    inline const m5::nfc::a::PICC& emulatePICC() const
    {
        return _picc;
    }
    //! @brief Gets the expiration time (ms)
    inline uint32_t expiredTime() const
    {
        return _expired_ms;
    }
    /*!
      @brief Sets the expiration time (ms)
      @param ms How long a state may last before the emulation returns to State::Off. Zero turns
      this off
      @note A reader that leaves in the middle of a session leaves the emulation waiting in that
      state, and nothing on the RF side tells it to stop. Going back to Off lets the next reader
      find it again. State::Off itself never expires
      @note The time is measured from the last RF traffic, so a session that keeps talking is not
      cut off however long it runs
     */
    void setExpiredTime(const uint32_t ms)
    {
        _expired_ms = ms;
    }

    //! @brief Begin NFC-A emulation
    bool begin(const m5::nfc::a::PICC& picc, uint8_t* ptr, const uint32_t size);
    //! @brief End NFC-A emulation
    bool end();
    //! @brief Update emulation state machine
    void update();

    /*!
      @brief Handles a command received from the reader
      @param rx Received frame (without CRC)
      @param rx_len Received length
      @return State to move to. State::Active keeps the emulation listening for the next command of
      the same session, State::Idle or State::Halt ends it
      @note Override this to answer commands that the library does not handle, and call
      EmulationLayerA::receive_callback for the rest. Answer with transmit()
     */
    virtual State receive_callback(const uint8_t* rx, const uint32_t rx_len);

protected:
    /*
      Return to State::Off when the current state has lasted longer than the expiration time
      @note Called at the top of update(). Does nothing while the time is zero, or in None/Off
     */
    void update_expired();
    /*
      Send a response to the reader
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if successful
     */
    bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms);

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
    uint32_t _expired_ms{10 * 1000u};
    m5::utility::elapsed_time_t _activity_at{};  // When RF traffic or a state change was last seen
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

    // Put the chip back to where it waits for a reader, from whatever state it is in. The default
    // does nothing, so an adapter that has no such step keeps working
    virtual EmulationLayerA::State reset_to_off()
    {
        return EmulationLayerA::State::Off;
    }

    // Whether the chip saw RF traffic since this was last asked, which also clears it. Answers the
    // chip sends by itself are included, since they never reach receive_callback. The default says
    // no, so an adapter that cannot tell falls back to timing state changes alone
    virtual bool consume_rf_activity()
    {
        return false;
    }
};
///@endcond

}  // namespace nfc
}  // namespace m5
#endif
