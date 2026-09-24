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
  - IDLE/READY/ACTIVE/HALT: internal state-machine names (borrowed from NFC-A's ISO14443-3 terminology for consistency)

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_F_EMULATION_LAYER_F_HPP
#define M5_UNIT_NFC_NFC_LAYER_F_EMULATION_LAYER_F_HPP

#include "nfc/f/nfcf.hpp"
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
  @class EmulationLayerF
  @brief Common interface layer for each chip of the NFC-F emulation
  @note The chip emulates one technology at a time, so this cannot run alongside EmulationLayerA.
  The unit must be configured for NFC-F emulation before begin().
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
    /*!
      @brief Construct with a chip adapter
      @param adapter Adapter that drives the chip
      @note Lets a chip this library does not know about be used without editing this header. The
      layer takes ownership of the adapter
      @warning The adapter must not be null
     */
    explicit EmulationLayerF(std::unique_ptr<Adapter> adapter);
    virtual ~EmulationLayerF();

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

    //! @brief Begin NFC-F emulation
    bool begin(const m5::nfc::f::PICC& picc, uint8_t* ptr, const uint32_t size);
    //! @brief End NFC-F emulation
    bool end();
    //! @brief Update emulation state machine
    void update();

    /*!
      @brief Handles a command received from the reader
      @param s Current state
      @param rx Received frame (without CRC)
      @param rx_len Received length
      @return State to move to. Returning s keeps the current state
      @note Override this to answer commands that the library does not handle, and call
      EmulationLayerF::receive_callback for the rest. Answer with transmit()
     */
    virtual State receive_callback(const State s, const uint8_t* rx, const uint32_t rx_len);

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
    void update_communicated();
    void update_selected();

protected:
    uint8_t* _memory{};
    uint32_t _memory_size{};

private:
    State _state{}, _prev{};
    uint32_t _expired_ms{10 * 1000u};
    m5::utility::elapsed_time_t _activity_at{};  // When RF traffic or a state change was last seen
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

    // Put the chip back to where it waits for a reader, from whatever state it is in. The default
    // does nothing, so an adapter that has no such step keeps working
    virtual EmulationLayerF::State reset_to_off()
    {
        return EmulationLayerF::State::Off;
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
