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
// #include "nfc/a/nfca.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace {
}

namespace m5 {
namespace nfc {

bool EmulationLayerA::begin(const m5::nfc::a::PICC& picc, uint8_t* ptr, const uint32_t size)
{
    if (_state != State::None) {
        M5_LIB_LOGW("Already started");
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
    return (_state != State::None);
}

bool EmulationLayerA::end()
{
    if (_state == State::None) {
        return true;
    }
    _state = State::None;
    return _impl->stop_emulation();
}

void EmulationLayerA::update()
{
    auto save = _state;

    switch (_state) {
        case State::None:
            break;
        case State::Off:
            if (_state != _prev) M5_LIB_LOGE("==OFF");
            update_off();
            break;
        case State::Idle:
            if (_state != _prev) M5_LIB_LOGE("==IDLE");
            update_idle();
            break;
        case State::Ready:
            if (_state != _prev) M5_LIB_LOGE("==READY");
            update_ready();
            break;
        case State::Active:
            if (_state != _prev) M5_LIB_LOGE("==ACTIVE");
            update_active();
            break;
        case State::Halt:
            if (_state != _prev) M5_LIB_LOGE("==HALT");
            update_halt();
            break;
        default:
            break;
    }
    _prev = save;
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
    M5_LIB_LOGE("cmd:%02X", rx[0]);

    State ret{State::Idle};
    switch (static_cast<Command>(rx[0])) {
        case Command::HLTA:
            ret = (rx_len == 2 && rx[1] == 0x00) ? State::Halt : State::Idle;
            break;
        case Command::READ:
            ret = (rx_len == 2) && _impl->transmit(_memory + _picc.unitSize() * rx[1], 16, 4) ? State::Active
                                                                                              : State::Idle;
            break;
        case Command::FAST_READ:
            break;
        default:
            break;
    }
    // M5_LIB_LOGE(" --> %u", ret);
    return ret;
}

}  // namespace nfc
}  // namespace m5
