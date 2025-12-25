/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_f.cpp
  @brief Emulation layer for NFC-F
*/
#include "emulation_layer_f.hpp"
#include "nfc/a/nfca.hpp"
#include <M5Utility.hpp>

using namespace m5::nfc;
using namespace m5::nfc::f;

#pragma GCC optimize("O3")

namespace {

constexpr uint32_t rc_offset       = 16u * (lite_s::REG.number + 1);
constexpr uint32_t wcnt_offset     = rc_offset + 16u * 9;
constexpr uint32_t crc_ceck_offset = wcnt_offset + 16u * 3;

uint8_t* block_to_address(uint8_t* mem, const uint32_t mem_size, const uint16_t block)
{
    if (!mem || !mem_size) {
        return nullptr;
    }

    uint32_t offset{mem_size};

    if (block <= lite_s::REG.number) {  // 0x00 - 0x0D
        offset = 16 * block;
    } else if (block <= lite_s::MC.number) {  // 0x80 - 0x88
        offset = rc_offset + 16 * (block - lite_s::RC.number);
    } else if (block <= lite_s::STATE.number) {  // 0x90 - 0x92
        offset = wcnt_offset + 16 * (block - lite_s::WCNT.number);
    } else if (block == lite_s::CRC_CHECK.number) {
        offset = crc_ceck_offset;
    }
    return (offset + 16 <= mem_size) ? (mem + offset) : nullptr;
}

inline bool is_system_code_ndef(const uint8_t sc[2])
{
    return sc && sc[0] == 0x12 && sc[1] == 0xFC;
}

inline bool is_system_code_lite(const uint8_t sc[2])
{
    return sc && sc[0] == 0x88 && sc[1] == 0xB4;
}

inline bool is_system_code_wildcard(const uint8_t sc[2])
{
    return sc && sc[0] == 0xFF && sc[1] == 0xFF;
}

}  // namespace

namespace m5 {
namespace nfc {

bool EmulationLayerF::begin(const m5::nfc::f::PICC& picc, uint8_t* ptr, const uint32_t size)
{
    if (_state != State::None) {
        M5_LIB_LOGW("Already started");
        return false;
    }

    /*
    if (!(picc.isNTAG() || picc.type == Type::MIFARE_Ultralight)) {
        M5_LIB_LOGE("Not support %u %s", picc.type, picc.typeAsString().c_str());
        return false;
    }
    */

    _picc        = picc;
    _memory      = ptr;
    _memory_size = size;

    /*
    if (!_picc.valid() || !_memory || _memory_size < _picc.totalSize()) {
        M5_LIB_LOGE("Invalid picc setting %s:%s %p %u/%u",  //
                    picc.uidAsString().c_str(), picc.typeAsString().c_str(), _memory, _memory_size, _picc.totalSize());
        return false;
    }
    */

    _state = _impl->start_emulation(_picc) ? State::Off : State::None;
    _prev  = State::None;

    _expired_at = m5::utility::millis() + _expired_ms;
    return (_state != State::None);
}

bool EmulationLayerF::end()
{
    if (_state == State::None) {
        return true;
    }
    _state = State::None;
    return _impl->stop_emulation();
}

void EmulationLayerF::update()
{
    auto save = _state;
    //    if (_state != _prev) {
    //        _expired_at = m5::utility::millis() + _expired_ms; // IRQ byGT ???
    //    }

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
        case State::Halt:
            if (_state != _prev) M5_LIB_LOGE("==HALT");
            update_halt();
            break;
        default:
            break;
    }
    _prev = save;
}

void EmulationLayerF::update_off()
{
    _state = _impl->update_off();
}

void EmulationLayerF::update_idle()
{
    _state = _impl->update_idle();
}

void EmulationLayerF::update_ready()
{
    _state = _impl->update_ready();
}

void EmulationLayerF::update_halt()
{
    _state = _impl->update_halt();
}

EmulationLayerF::State EmulationLayerF::receive_callback(const State s, const uint8_t* rx, const uint32_t rx_len)
{
    if (!rx || rx_len < 2) {
        return State::Idle;
    }

    State ret = s;
    switch (static_cast<CommandCode>(rx[1])) {
        case CommandCode::Polling:
            //             m5::utility::log::dump(rx, rx_len, false);
            //            M5_LIB_LOGE("  PO:%u,%u,%u", is_system_code_lite(rx + 2), is_system_code_ndef(rx + 2),
            //                        is_system_code_wildcard(rx + 2));
            if (rx_len == 6 &&
                (is_system_code_lite(rx + 2) || is_system_code_ndef(rx + 2) || is_system_code_wildcard(rx + 2))) {
                uint8_t SENS_RES_NDEF[1 + 8 + 8] = {m5::stl::to_underlying(ResponseCode::Polling)};
                memcpy(SENS_RES_NDEF + 1, _picc.m, 16);
                if (is_system_code_ndef(rx + 2)) {
                    auto ptr = block_to_address(_memory, _memory_size, lite_s::MC.number);
                    if (!ptr || ptr[3] == 0x00) {  // SYS_OP is not support NDEF
                        //                        M5_LIB_LOGE("   NOT NDEF");
                        break;
                    }
                }
                M5_LIB_LOGE(" SRES:%02X%02X", rx[2], rx[3]);
                ret = _impl->transmit(SENS_RES_NDEF, sizeof(SENS_RES_NDEF), 2) ? State::Ready : s;
            }
            break;
        case CommandCode::ReadWithoutEncryption: {
            M5_LIB_LOGE("RD:");
            //           m5::utility::log::dump(rx, rx_len, false);
            // 10 06 02 FE 56 78 9A BC DE F0 01 0B 00 01 80 A0
            if (rx_len >= 15 && memcmp(_picc.idm, rx + 2, sizeof(_picc.idm)) == 0) {
                std::vector<uint8_t> tx{};
                tx.resize(1 + 1 + 8 + 2 + 1 + 16 * rx[13]);

                uint32_t offset{};
                tx[offset++] = m5::stl::to_underlying(ResponseCode::ReadWithoutEncryption);  // Response code
                memcpy(tx.data() + 2, _picc.idm, 8);                                         // IDm
                offset += 8;
                tx[offset++]          = 0;  // Status 1
                tx[offset++]          = 0;  // Status 2
                tx[offset++]          = 0;  // Number of blocks
                uint32_t block_offset = 14;
                for (uint_fast8_t i = 0; i < rx[13]; ++i) {
                    block_t b = block_t::from(rx + block_offset);
                    block_offset += 2 + b.is_3byte();
                    auto ptr = block_to_address(_memory, _memory_size, b.block());
                    if (!ptr) {
                        tx[9]  = 1U << i;  // Error block bit
                        tx[10] = 0xA8;     // Invalid block
                        tx.resize(1 + 8 + 2);
                        break;
                    }
                    memcpy(tx.data() + offset, ptr, 16);
                    offset += 16;
                }
                if (!tx[0]) {
                    tx[11] = rx[13];
                }
                // m5::utility::log::dump(tx.data(), tx.size(), false);
                ret = _impl->transmit(tx.data(), tx.size(), tx.size() * 2) ? State::Ready : s;
            }
        } break;
        default:
            break;
    }
    // M5_LIB_LOGE(" --> %u", ret);
    return ret;
}

}  // namespace nfc
}  // namespace m5
