/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_a.cpp
  @brief Emulation layer for NFC-A
*/
#include "emulation_layer_a.hpp"
#include "nfc/a/nfca.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

// clang-format off
//#pragma GCC optimize("O3")
// clang-format on

namespace {
constexpr uint8_t dummy_signature[32] = {};

}  // namespace

namespace m5 {
namespace nfc {

EmulationLayerA::~EmulationLayerA() = default;

bool EmulationLayerA::begin(const m5::nfc::a::PICC& picc, uint8_t* ptr, const uint32_t size)
{
    if (_state != State::None) {
        M5_LIB_LOGW("Already started");
        return false;
    }

    if (!(picc.isNTAG2() || picc.type == Type::MIFARE_Ultralight)) {
        M5_LIB_LOGE("Not support %u %s", picc.type, picc.typeAsString().c_str());
        return false;
    }

    _picc        = picc;
    _memory      = ptr;
    _memory_size = size;

    if (!_picc.valid() || !_memory || _memory_size < _picc.totalSize()) {
        M5_LIB_LOGE("Invalid picc setting %s:%s %p %u/%u",  //
                    picc.uidAsString().c_str(), picc.typeAsString().c_str(), _memory, _memory_size, _picc.totalSize());
        return false;
    }

    _state = _impl->start_emulation(_picc) ? State::Off : State::None;
    _prev  = State::None;

    _activity_at = m5::utility::millis();
    return (_state != State::None);
}

bool EmulationLayerA::end()
{
    if (_state == State::None) {
        M5_LIB_LOGW("Not started");
        return true;
    }
    _state = State::None;
    return _impl->stop_emulation();
}

void EmulationLayerA::update_expired()
{
    // A reader that walks away in the middle of a session leaves the emulation waiting in that
    // state, and nothing on the RF side will tell it to stop. Going back to Off after a while
    // makes the next reader find it again
    if (!_expired_ms || _state == State::None || _state == State::Off) {
        return;
    }
    if (m5::utility::hasElapsed(_activity_at, _expired_ms)) {
        M5_LIB_LOGI("Expired in state:%u, back to off", static_cast<unsigned>(_state));
        _state       = _impl->reset_to_off();
        _activity_at = m5::utility::millis();
    }
}

void EmulationLayerA::update()
{
    auto save = _state;

    update_expired();

    switch (_state) {
        case State::None:
            break;
        case State::Off:
            if (_state != _prev) M5_LIB_LOGD("==OFF");
            update_off();
            break;
        case State::Idle:
            if (_state != _prev) M5_LIB_LOGD("==IDLE");
            update_idle();
            break;
        case State::Ready:
            if (_state != _prev) M5_LIB_LOGD("==READY");
            update_ready();
            break;
        case State::Active:
            if (_state != _prev) M5_LIB_LOGD("==ACTIVE");
            update_active();
            break;
        case State::Halt:
            if (_state != _prev) M5_LIB_LOGD("==HALT");
            update_halt();
            break;
        default:
            break;
    }
    // Asked every round and not only when the state moved, so that a session that keeps talking
    // inside one state is not mistaken for a reader that walked away
    const bool active = _impl->consume_rf_activity();
    if (_state != save || active) {
        _activity_at = m5::utility::millis();
    }
    _prev = save;
}

bool EmulationLayerA::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    return _impl && tx && tx_len ? _impl->transmit(tx, tx_len, timeout_ms) : false;
}

void EmulationLayerA::update_off()
{
    _state = _impl->update_off();
}

void EmulationLayerA::update_idle()
{
    _state = _impl->update_idle();
}

void EmulationLayerA::update_ready()
{
    _state = _impl->update_ready();
}

void EmulationLayerA::update_active()
{
    _state = _impl->update_active();
}

void EmulationLayerA::update_halt()
{
    _state = _impl->update_halt();
}

EmulationLayerA::State EmulationLayerA::receive_callback(const uint8_t* rx, const uint32_t rx_len)
{
    if (!rx || !rx_len) {
        return State::Idle;
    }
    // m5::utility::log::dump(rx, rx_len, false);

    State ret{State::Idle};
    switch (static_cast<Command>(rx[0])) {
        case Command::HLTA:
            ret = (rx_len == 2 && rx[1] == 0x00) ? State::Halt : State::Idle;
            break;
        case Command::READ: {  // 16 bytes read
            // The page is the reader's to choose, so without this the answer would carry whatever
            // sits past the emulated memory out over the air
            const uint32_t offset = _picc.unitSize() * rx[1];
            ret = (rx_len == 2) && (offset + 16 <= _memory_size) && _impl->transmit(_memory + offset, 16, 4)
                      ? State::Active
                      : State::Idle;
        } break;
        case Command::FAST_READ:
            if (rx_len == 3) {
                const uint32_t from = rx[1];
                const uint32_t to   = rx[2];
                const uint32_t cnt  = to - from + 1;
                // The bound is in bytes while the addresses are pages, so the last byte actually
                // touched is four times the end page plus three
                if (from <= to && 4 * to + 4 <= _memory_size) {
                    ret = _impl->transmit(_memory + 4 * from, 4 * cnt, cnt) ? State::Active : State::Idle;
                }
            }
            break;
        case Command::GET_VERSION:
            if (rx_len == 1) {
                const auto res = get_version3_response(_picc.type);  // fiexd 8 bytes
                if (res) {
                    ret = _impl->transmit(res, 8, 2) ? State::Active : State::Idle;
                }
            }
            break;
        case Command::WRITE_BLOCK:
            // 2 step!
            break;
        case Command::WRITE_PAGE: {
            if (rx_len == 6) {
                const uint32_t offset = 4 * rx[1];
                if (offset + 4 <= _memory_size) {
                    memcpy(_memory + offset, rx + 2, 4);
                    //                    ret = _impl->send_ack() ? State::Active : State::Idle;  // Return ACK
                    ret = _impl->transmit(&ACK_NIBBLE, 1, 1) ? State::Active : State::Idle;  // Return ACK
                }
            }
        } break;
        case Command::READ_SIG:
            if (_picc.isNTAG2() || _picc.type == Type::MIFARE_Ultralight_EV1_1 ||
                _picc.type == Type::MIFARE_Ultralight_EV1_2 || _picc.type == Type::MIFARE_Ultralight_Nano) {
                if (rx_len == 2 && rx[1] == 0x00 /*RFU*/) {
                    ret = _impl->transmit(dummy_signature, sizeof(dummy_signature), 4) ? State::Active : State::None;
                }
            }
            break;

        default:
            M5_LIB_LOGE("CMD:%02X %u", rx[0], rx_len);
            break;
    }
    // M5_LIB_LOGE(" --> %u", ret);
    return ret;
}

}  // namespace nfc
}  // namespace m5
