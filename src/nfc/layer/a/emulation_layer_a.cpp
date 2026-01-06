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

bool EmulationLayerA::begin(const m5::nfc::a::PICC& picc, uint8_t* ptr, const uint32_t size)
{
    if (_state != State::None) {
        M5_LIB_LOGW("Already started");
        return false;
    }

    if (!(picc.isNTAG() || picc.type == Type::MIFARE_Ultralight)) {
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

    _expired_at = m5::utility::millis() + _expired_ms;
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
    //    if (_state != _prev) {
    //        _expired_at = m5::utility::millis() + _expired_ms; // IRQ byGT ???
    //    }

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

    State ret{State::Idle};
    switch (static_cast<Command>(rx[0])) {
        case Command::HLTA:
            ret = (rx_len == 2 && rx[1] == 0x00) ? State::Halt : State::Idle;
            break;
        case Command::READ:  // 16 bytes read
            ret = (rx_len == 2) && _impl->transmit(_memory + _picc.unitSize() * rx[1], 16, 4) ? State::Active
                                                                                              : State::Idle;
            break;
        case Command::FAST_READ:
            if (rx_len == 3) {
                const uint32_t from = rx[1];
                const uint32_t to   = rx[2];
                const uint32_t cnt  = to - from + 1;
                if (from <= to && from + 4 <= _memory_size && to + 4 <= _memory_size) {
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
            if (_picc.isNTAG() || _picc.type == Type::MIFARE_Ultralight_EV1_1 ||
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
