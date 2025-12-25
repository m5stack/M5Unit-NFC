/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_f_ST25R3916.cpp
  @brief ST25R3916 NFC-F emulation adapter for common layer
*/
#include "nfc/layer/f/emulation_layer_f.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "unit/unit_ST25R3916.hpp"
#include <M5Utility.hpp>
#include <thread>
#include <numeric>
#include <algorithm>

using namespace m5::unit;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::command;
using namespace m5::unit::st25r3916::regval;
using namespace m5::nfc;
using namespace m5::nfc::f;

#pragma GCC optimize("O3")

namespace {
inline bool is_eof(const uint32_t irq)
{
    return (irq & I_eof32);
}

inline uint32_t OCB(const uint8_t c)
{
    // printf("%08o", OCB(0x2d)); => 00101101
    return (c & 1) | (c & 2) << 2 | (c & 4) << 4 | (c & 8) << 6 | (c & 16) << 8 | (c & 32) << 10 | (c & 64) << 12 |
           (c & 128) << 14;
}

constexpr uint8_t mode_mask{0xFB};  // targ,om0123,ar01
constexpr uint8_t mode_bitrate_detection = targ | (0x0Cu << 3);
constexpr uint8_t mode_listen_nfc_f      = targ | (0x04 << 3);

constexpr uint32_t mode_irq    = I_wu_f32 | I_rxe32;
constexpr uint32_t default_irq = I_nfct32 | I_rxs32 | I_eon32 | I_eof32 | I_crc32 | I_err132 | I_err232;

struct ESP32Rng {
    using result_type = uint32_t;
    static result_type min()
    {
        return 0;
    }
    static result_type max()
    {
        return UINT32_MAX;
    }
    result_type operator()()
    {
        return esp_random();
    }
};

}  // namespace

namespace m5 {
namespace nfc {
struct ListenerST25R3916ForF final : EmulationLayerF::Adapter {
    explicit ListenerST25R3916ForF(EmulationLayerF& layer, UnitST25R3916& ref) : _layer{layer}, _u{ref}
    {
    }
    /*
    inline virtual uint16_t max_fifo_depth() override
    {
        return m5::unit::st25r3916::MAX_FIFO_DEPTH;
    }
    */

    virtual bool start_emulation(const m5::nfc::f::PICC& picc) override;
    virtual bool stop_emulation() override;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) override;

    //
    virtual EmulationLayerF::State update_off() override;
    virtual EmulationLayerF::State update_idle() override;
    virtual EmulationLayerF::State update_ready() override;
    virtual EmulationLayerF::State update_halt() override;

    //
    EmulationLayerF::State goto_state(const EmulationLayerF::State s);
    EmulationLayerF::State goto_off();
    EmulationLayerF::State goto_idle();
    EmulationLayerF::State goto_ready();
    EmulationLayerF::State goto_halt();

    bool load_config(const m5::nfc::f::PICC& picc);

    //
    uint32_t get_irq(const uint32_t mask_bits);

    bool is_extra_field();

    //    enum State{ None, Off, Idle, Ready, Active, Halt };
    Bitrate _bitrate{Bitrate::Invalid};
    uint32_t _receive_bits{};
    bool _data_flag{};
    bool _wakeup{};

    EmulationLayerF& _layer;
    UnitST25R3916& _u;
};

uint32_t ListenerST25R3916ForF::get_irq(const uint32_t bits)
{
    if (_u._interrupt_occurred) {  // In I2C, Unit::update acquires IRQ each time.
        _u._interrupt_occurred = false;
        uint32_t v{};
        (void)_u.readInterrupts(v);
        _u._stored_irq |= v;
    }
    uint32_t irq32 = _u._stored_irq & bits;
    if (irq32) {
        _u._stored_irq &= ~irq32;
    }
    return irq32;
}

bool ListenerST25R3916ForF::load_config(const m5::nfc::f::PICC& picc)
{
    if (!picc.valid()) {
        M5_LIB_LOGE("Invalid PICC");
        return false;
    }

    uint8_t wbuf[21]{};
    uint32_t offset{};
    // SC(2)
    wbuf[offset++] = picc.emulation_sc >> 8;
    wbuf[offset++] = picc.emulation_sc & 0xFF;
    // SENSF_RES(19)
    wbuf[offset++] = m5::stl::to_underlying(ResponseCode::Polling);
    memcpy(wbuf + offset, picc.m, 16);
    offset += 16;
    wbuf[offset++] = 0;  // SENSF_REQ, request code 0x01/0x02 NOT support ST25R3916
    wbuf[offset++] = 0;  // SENSF_REQ, request code 0x01/0x02 NOT support ST25R3916

    //    m5::utility::log::dump(wbuf, offset, false);

    // TSN: 24 4-bit random numbers are stored
    // Make it as even as possible
    ESP32Rng rng;
    uint8_t tsn[12]{};
    uint8_t pool[16]{};
    uint8_t tmp[24]{};
    std::iota(pool, pool + sizeof(pool), 0);  // make 0 ... 15

    std::shuffle(pool, pool + sizeof(pool), rng);
    memcpy(tmp, pool, 16);  // The first 16 are unique
    std::shuffle(pool, pool + sizeof(pool), rng);
    memcpy(tmp + 16, pool, 8);

    for (uint_fast8_t i = 0; i < 12; ++i) {
        const uint8_t high = tmp[i * 2] & 0x0F;
        const uint8_t low  = tmp[i * 2 + 1] & 0x0F;
        tsn[i]             = static_cast<uint8_t>((high << 4) | low);
    }
    return _u.writePtMemoryF(wbuf, sizeof(wbuf)) && _u.writePtMemoryTSN(tsn, sizeof(tsn));
}

bool ListenerST25R3916ForF::start_emulation(const m5::nfc::f::PICC& picc)
{
    if (!load_config(picc)) {
        return false;
    }

    if (0) {
        uint8_t rbuf[PT_MEMORY_LENGTH]{};
        _u.readPtMemory(rbuf, sizeof(rbuf));
        m5::utility::log::dump(rbuf, PT_MEMORY_LENGTH, false);
    }

    // Auto response  only NFC-F
    _u.change_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_ac_ap2p | d_106_ac_a,
                            d_ac_ap2p | d_212_424_1r | d_106_ac_a);
    //_u.change_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_ac_ap2p | d_106_ac_a|d_212_424_1r,
    //                            d_ac_ap2p | d_212_424_1r | d_106_ac_a);

    // Disable GPT trigger source
    _u.change_bit_register8(REG_TIMER_AND_EMV_CONTROL, 0x00, 0xE0);

    // 512/fc steps
    _u.set_bit_register8(REG_TIMER_AND_EMV_CONTROL, mrt_step);
    _u.write_register8(REG_MASK_RECEIVER_TIMER, calculate_mrt(100, true));  // 100us
    // 14443-A enable parity , disable NFCIP-1
    _u.clear_bit_register8(REG_ISO14443A_SETTINGS, no_tx_par | no_rx_par | nfc_f0);

    _u.writeAntennaTuningControl1(0x00);
    _u.writeAntennaTuningControl2(0xFF);
    _u.writeOvershootProtectionConfiguration1(0x00);
    _u.writeOvershootProtectionConfiguration2(0x00);
    _u.writeUndershootProtectionConfiguration1(0x00);
    _u.writeUndershootProtectionConfiguration2(0x00);

    _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);

    (void)goto_off();
    return true;
}

bool ListenerST25R3916ForF::stop_emulation()
{
    ///    /*Check if Observation Mode was enabled and disable it on ST25R391x */
    //    rfalCheckDisableObsMode();

    return _u.enable_osc() && _u.disable_field() &&
           _u.set_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_ac_ap2p | d_212_424_1r | d_106_ac_a) &&
           _u.writeModeDefinition(0x00);
}

bool ListenerST25R3916ForF::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    return _u.nfcfTransmit(tx, tx_len, timeout_ms);
}

// ------------------------------------------------------------
EmulationLayerF::State ListenerST25R3916ForF::goto_state(const EmulationLayerF::State s)
{
    switch (s) {
        case EmulationLayerF::State::Off:
            return goto_off();
        case EmulationLayerF::State::Idle:
            return goto_idle();
        case EmulationLayerF::State::Ready:
            return goto_ready();
        case EmulationLayerF::State::Halt:
            return goto_halt();
        default:
            break;
    }
    return goto_off();
}

EmulationLayerF::State ListenerST25R3916ForF::goto_off()
{
    _data_flag    = false;
    _bitrate      = Bitrate::Invalid;
    _receive_bits = 0;
    _wakeup       = false;

    _u.writeDirectCommand(CMD_STOP_ALL_ACTIVITIES);
    _u.set_bit_register8(REG_OPERATION_CONTROL, rx_en);

    _u.clear_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_212_424_1r);  // Enable auto response for NFC-F
    _u.clear_bit_register8(REG_ISO14443A_SETTINGS, nfc_f0);

    _u.writeMaskInterrupts(0xFFFFFFFF);
    _u.clearInterrupts();
    _u.enable_interrupts(I_osc32 | default_irq | mode_irq);

    _u.set_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx);

    // Set mode: om -> FeliCa + bit rate detection mode
    _u.change_bit_register8(REG_MODE_DEFINITION, mode_bitrate_detection, 0x78);

    if (is_extra_field()) {
        M5_LIB_LOGE("off->idle");
        return goto_idle();
    } else {
        _u.clear_bit_register8(REG_OPERATION_CONTROL, tx_en | rx_en | en);
    }
    return EmulationLayerF::State::Off;
}

EmulationLayerF::State ListenerST25R3916ForF::goto_idle()
{
    uint8_t v{}, aux{};

    _data_flag = false;
    if (_u.readOperationControl(v) && ((v & en) == 0)) {
        _u.set_bit_register8(REG_OPERATION_CONTROL, (en | rx_en));
        if (_u.readAuxiliaryDisplay(aux) && ((aux & osc_ok) == 0)) {
            if ((_u.wait_for_interrupt(I_osc32, 1000) & I_osc32) == 0) {
                M5_LIB_LOGE("Oscillator not ready");
                return goto_off();
            }
        }
    } else {
        (void)get_irq(I_osc32);
    }

    _u.set_bit_register8(REG_AUXILIARY_DEFINITION, no_crc_rx);

    _u.writeDirectCommand(CMD_CLEAR_FIFO);
    _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
    //       rfalCheckEnableObsModeRx();

    _wakeup = false;

    _u.update();
    return update_idle();
    return EmulationLayerF::State::Idle;
}

EmulationLayerF::State ListenerST25R3916ForF::goto_ready()
{
    _data_flag = false;

    _u.writeBitrate(_bitrate, _bitrate);
    _u.clear_bit_register8(REG_OPERATION_CONTROL, wu);  // Disable wakeup mode

    _u.writeModeDefinition(mode_listen_nfc_f);
    _u.writeDirectCommand(CMD_CLEAR_FIFO);
    _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);

    (void)get_irq(I_par32 | I_crc32 | I_err232 | I_err132);
    _u.enable_interrupts(I_rxe32);

    _u.update();
    return update_ready();
    return EmulationLayerF::State::Ready;
}

EmulationLayerF::State ListenerST25R3916ForF::goto_halt()
{
    _data_flag = false;

    _u.clear_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_106_ac_a);  // Enable auto response for NFC-A
    _u.writeDirectCommand(CMD_GO_TO_SLEEP);
    _u.change_bit_register8(REG_MODE_DEFINITION, mode_bitrate_detection, mode_mask);

    _u.clear_bit_register8(REG_ISO14443A_SETTINGS, nfc_f0);
    _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
    _u.enable_interrupts(I_nfct32 | I_rxs32 | I_crc32 | I_err132 | I_err232 | I_par32 | I_eon32 | I_eof32 | mode_irq);

    if (!is_extra_field()) {
        return goto_off();
    }

    _u.update();
    return update_halt();
    return EmulationLayerF::State::Halt;
}

// ------------------------------------------------------------
EmulationLayerF::State ListenerST25R3916ForF::update_off()
{
    // IRQ due to detection of external field
    if ((get_irq(I_eon32) & I_eon32)) {
        return goto_idle();
    }
    return EmulationLayerF::State::Off;
}

EmulationLayerF::State ListenerST25R3916ForF::update_idle()
{
    uint32_t irq32 = get_irq(I_nfct32 | I_rxe32 | I_eof32 | I_wu_f32);

    if (!irq32) {
        return EmulationLayerF::State::Idle;
    }

    // initiator bit rate was recognized
    if (irq32 & I_nfct32) {
        uint8_t br{};
        _u.readBitrateDetectionDisplay(br);
        br = (br >> 4) & 0x03;  // 0:106 1:212 2:424 3:848
        if (br > 2) {
            br = 2;
        }
        _bitrate = static_cast<Bitrate>(br);
    }

    if (is_eof(irq32) && !_data_flag) {
        return goto_off();
    }

    if ((irq32 & I_wu_f32) && _bitrate != Bitrate::Invalid) {
        return goto_ready();
    }

    if ((irq32 & I_rxe32) && _bitrate != Bitrate::Invalid) {
        irq32 |= get_irq(I_rxe32 | I_eof32 | I_crc32 | I_par32 | I_err232 | I_err132);
        if (irq32 & (I_crc32 | I_par32 | I_err132)) {
            _u.writeDirectCommand(CMD_CLEAR_FIFO);
            _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
            _u.clear_bit_register8(REG_OPERATION_CONTROL, tx_en);
            return EmulationLayerF::State::Idle;
        }
        uint16_t bytes{};
        uint8_t bits{};
        uint8_t rx[128]{};
        uint16_t rx_len{}, actual{};
        _u.readFIFOSize(bytes, bits);
        rx_len = std::min<uint16_t>(bytes, sizeof(rx));
        _u.readFIFO(actual, rx, rx_len);
        _data_flag = true;
        if (actual) {
            auto state = _layer.receive_callback(EmulationLayerF::State::Idle, rx, rx[0]);
            if (state != EmulationLayerF::State::Idle) {
                return goto_state(state);
            }
            return goto_ready();
        }
    }
    return EmulationLayerF::State::Idle;
}

EmulationLayerF::State ListenerST25R3916ForF::update_ready()
{
    uint32_t irq32 = get_irq(I_eof32 | I_wu_f32 | I_rxe32);  // Clear I_wu_f32, Not use
    if (!irq32) {
        return EmulationLayerF::State::Ready;
    }

    if (is_eof(irq32)) {
        return goto_off();
    }
    if (irq32 & I_rxe32) {
        irq32 |= get_irq(I_crc32 | I_err232 | I_err132);
        if (irq32 & (I_crc32 | I_err132)) {
            _u.writeDirectCommand(CMD_CLEAR_FIFO);
            _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
            return EmulationLayerF::State::Ready;
        }
        uint16_t bytes{};
        uint8_t bits{};
        uint8_t rx[128]{};
        uint16_t rx_len{}, actual{};
        _u.readFIFOSize(bytes, bits);
        rx_len = std::min<uint16_t>(bytes, sizeof(rx));
        _u.readFIFO(actual, rx, rx_len);
        _data_flag = true;
        if (actual) {
            auto state = _layer.receive_callback(EmulationLayerF::State::Idle, rx, rx[0]);
            if (state != EmulationLayerF::State::Ready) {
                return goto_state(state);
            }
        }
    }

    return EmulationLayerF::State::Ready;
}

EmulationLayerF::State ListenerST25R3916ForF::update_halt()
{
    auto irq32 = get_irq(I_nfct32 | I_rxe32 | I_eof32 | I_wu_f32);
    if (!irq32) {
        return EmulationLayerF::State::Halt;
    }

    // initiator bit rate was recognized
    if ((irq32 & I_nfct32) && _bitrate == Bitrate::Invalid) {
        // M5_LIB_LOGE("  >> BR");
        uint8_t br{};
        _u.readBitrateDetectionDisplay(br);
        br = (br >> 4) & 0x03;  // 0:106 1:212 2:424 3:848
        if (br > 2) {
            br = 2;
        }
        _bitrate = static_cast<Bitrate>(br);
    }
    if (is_eof(irq32)) {
        // M5_LIB_LOGE("  >> OFF");
        return goto_off();
    }
    if (irq32 & I_wu_f32) {
        return goto_ready();
    }

    if ((irq32 & I_rxe32) && _bitrate != Bitrate::Invalid) {
        // M5_LIB_LOGE("  >> RX");
        _u.writeDirectCommand(CMD_CLEAR_FIFO);
        _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
        return EmulationLayerF::State::Halt;
    }
    return EmulationLayerF::State::Halt;
}

bool ListenerST25R3916ForF::is_extra_field()
{
    uint8_t v{};
    return _u.readAuxiliaryDisplay(v) && (v & efd_o);
}

//
namespace {
std::unique_ptr<EmulationLayerF::Adapter> make_st25r3916_adapter(EmulationLayerF& l, UnitST25R3916& u)
{
    return std::unique_ptr<EmulationLayerF::Adapter>(new ListenerST25R3916ForF(l, u));
}
}  // namespace

EmulationLayerF::EmulationLayerF(UnitST25R3916& u) : _impl(make_st25r3916_adapter(*this, u))
{
}

EmulationLayerF::EmulationLayerF(CapST25R3916& u) : _impl(make_st25r3916_adapter(*this, static_cast<UnitST25R3916&>(u)))
{
}

}  // namespace nfc
}  // namespace m5
