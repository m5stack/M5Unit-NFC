/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file emulation_layer_a_ST25R3916.cpp
  @brief ST25R3916 NFC-A emulation adapter for common layer
*/
#include "nfc/layer/a/emulation_layer_a.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "unit/unit_ST25R3916.hpp"
#include <M5Utility.hpp>
#include <thread>

using namespace m5::unit;
using namespace m5::unit::st25r3916;
using namespace m5::unit::st25r3916::command;
using namespace m5::unit::st25r3916::regval;
using namespace m5::nfc;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

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
constexpr uint8_t mode_bitrate_detection = targ | (0x09u << 3);
constexpr uint8_t mode_listen_nfc_a      = targ | (0x01 << 3);

constexpr uint32_t mode_irq    = I_wu_a32 | I_wu_ax32 | I_rxe_pta32;
constexpr uint32_t default_irq = I_nfct32 | I_rxs32 | I_eon32 | I_eof32 | I_crc32 | I_err132 | I_err232 | I_par32;

}  // namespace

namespace m5 {
namespace nfc {
struct ListenerST25R3916ForA final : EmulationLayerA::Adapter {
    explicit ListenerST25R3916ForA(EmulationLayerA& layer, UnitST25R3916& ref) : _layer{layer}, _u{ref}
    {
    }
    /*
    inline virtual uint16_t max_fifo_depth() override
    {
        return m5::unit::st25r3916::MAX_FIFO_DEPTH;
    }
    */

    virtual bool start_emulation(const m5::nfc::a::PICC& picc) override;
    virtual bool stop_emulation() override;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) override;

    //
    virtual EmulationLayerA::State update_off() override;
    virtual EmulationLayerA::State update_idle() override;
    virtual EmulationLayerA::State update_ready() override;
    virtual EmulationLayerA::State update_active() override;
    virtual EmulationLayerA::State update_halt() override;

    //
    EmulationLayerA::State goto_state(const EmulationLayerA::State s);
    EmulationLayerA::State goto_off();
    EmulationLayerA::State goto_idle();
    EmulationLayerA::State goto_ready();
    EmulationLayerA::State goto_active();
    EmulationLayerA::State goto_halt();

    bool load_config(const m5::nfc::a::PICC& picc);

    //
    uint32_t get_irq(const uint32_t mask_bits);

    bool is_extra_field();

    //    enum State{ None, Off, Idle, Ready, Active, Halt };
    Bitrate _bitrate{Bitrate::Invalid};
    uint32_t _receive_bits{};
    bool _data_flag{};
    bool _wakeup{};

    EmulationLayerA& _layer;
    UnitST25R3916& _u;
};

uint32_t ListenerST25R3916ForA::get_irq(const uint32_t bits)
{
    if (!_u._using_irq || _u._interrupt_occurred) {
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

bool ListenerST25R3916ForA::load_config(const m5::nfc::a::PICC& picc)
{
    if (!picc.valid() || picc.size == 10) {  // 10 bytes uid not supported
        M5_LIB_LOGE("Invalid PICC");
        return false;
    }

    uint8_t wbuf[15]{};
    uint32_t offset{};

    // UID
    memcpy(wbuf, picc.uid, picc.size);
    offset += 10;
    // ATQA
    wbuf[offset++] = picc.atqa & 0xFF;
    wbuf[offset++] = picc.atqa >> 8;
    // SAK (lv1-3)
    wbuf[offset++] = (picc.size == 4) ? (picc.sak & ~0x04) : (picc.sak | 0x04 /* incomplete */);
    wbuf[offset++] = (picc.sak & ~0x04);
    wbuf[offset++] = (picc.sak & ~0x04);

    constexpr uint8_t uid_4{0x00};
    constexpr uint8_t uid_7{0x10};
    return _u.change_bit_register8(REG_AUXILIARY_DEFINITION, ((picc.size == 7) ? uid_7 : uid_4), 0x30) &&
           _u.writePtMemoryA(wbuf, offset);
}

bool ListenerST25R3916ForA::start_emulation(const m5::nfc::a::PICC& picc)
{
    if (!load_config(picc)) {
        return false;
    }

    if (0) {
        uint8_t rbuf[PT_MEMORY_LENGTH]{};
        _u.readPtMemory(rbuf, sizeof(rbuf));
        m5::utility::log::dump(rbuf, PT_MEMORY_LENGTH, false);
    }

    // Auto response  only NFC-A
    _u.change_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_ac_ap2p | d_212_424_1r,
                            d_ac_ap2p | d_212_424_1r | d_106_ac_a);

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

bool ListenerST25R3916ForA::stop_emulation()
{
    ///    /*Check if Observation Mode was enabled and disable it on ST25R391x */
    //    rfalCheckDisableObsMode();

    return _u.enable_osc() && _u.disable_field() &&
           _u.set_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_ac_ap2p | d_212_424_1r | d_106_ac_a) &&
           _u.writeModeDefinition(0x00);
}

bool ListenerST25R3916ForA::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
{
    return _u.nfcaTransmit(tx, tx_len, timeout_ms);
}

#if 0
            puts("SetMode RFAL_MODE_LISTEN_NFCA");
            /* Disable wake up mode, if set */
            st25r3916ClrRegisterBits(ST25R3916_REG_OP_CONTROL, ST25R3916_REG_OP_CONTROL_wu);

            /* Enable Passive Target NFC-A mode, disable any Collision Avoidance */
            st25r3916WriteRegister(ST25R3916_REG_MODE, (ST25R3916_REG_MODE_targ | ST25R3916_REG_MODE_om_targ_nfca |
                                                        ST25R3916_REG_MODE_nfc_ar_off));

            /* Set Analog configurations for this mode */
            rfalSetAnalogConfig((RFAL_ANALOG_CONFIG_LISTEN | RFAL_ANALOG_CONFIG_TECH_NFCA |
                                 RFAL_ANALOG_CONFIG_BITRATE_COMMON | RFAL_ANALOG_CONFIG_TX));
            rfalSetAnalogConfig((RFAL_ANALOG_CONFIG_LISTEN | RFAL_ANALOG_CONFIG_TECH_NFCA |
                                 RFAL_ANALOG_CONFIG_BITRATE_COMMON | RFAL_ANALOG_CONFIG_RX));
#endif

// ------------------------------------------------------------
EmulationLayerA::State ListenerST25R3916ForA::goto_state(const EmulationLayerA::State s)
{
    switch (s) {
        case EmulationLayerA::State::Off:
            return goto_off();
        case EmulationLayerA::State::Idle:
            return goto_idle();
        case EmulationLayerA::State::Ready:
            return goto_ready();
        case EmulationLayerA::State::Active:
            return goto_active();
        case EmulationLayerA::State::Halt:
            return goto_halt();
        default:
            break;
    }
    return goto_off();
}

EmulationLayerA::State ListenerST25R3916ForA::goto_off()
{
    _data_flag    = false;
    _bitrate      = Bitrate::Invalid;
    _receive_bits = 0;
    _wakeup       = false;

    _u.writeDirectCommand(CMD_STOP_ALL_ACTIVITIES);
    _u.set_bit_register8(REG_OPERATION_CONTROL, rx_en);

    _u.clear_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_106_ac_a);  // Enable auto response for NFC-A
    _u.writeDirectCommand(CMD_GO_TO_SENSE);
    _u.clear_bit_register8(REG_ISO14443A_SETTINGS, nfc_f0);

    // Set mode: om -> ISO14443A + bti detection moed
    _u.change_bit_register8(REG_MODE_DEFINITION, targ | (0x09 << 3), 0x78);

    _u.writeMaskInterrupts(0xFFFFFFFF);
    _u.clearInterrupts();
    _u.enable_interrupts(I_nfct32 | I_rxs32 | I_crc32 | I_err132 | I_osc32 | I_err232 | I_par32 | I_eon32 | I_eof32 |
                         mode_irq);

    if (is_extra_field()) {
        return goto_idle();
    } else {
        _u.clear_bit_register8(REG_OPERATION_CONTROL, tx_en | rx_en | en);
    }
    return EmulationLayerA::State::Off;
}

EmulationLayerA::State ListenerST25R3916ForA::goto_idle()
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

    if (_layer.state() == EmulationLayerA::State::Active && !_wakeup) {
        M5_LIB_LOGE("   >> Active to idle");
        _u.clear_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_106_ac_a);  // Enable auto response for NFC-A
        _u.writeDirectCommand(CMD_GO_TO_SENSE);
    }

    _u.writeDirectCommand(CMD_CLEAR_FIFO);
    _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
    //       rfalCheckEnableObsModeRx();

    _wakeup = false;
    return EmulationLayerA::State::Idle;
}

EmulationLayerA::State ListenerST25R3916ForA::goto_ready()
{
    _data_flag = false;
    if (get_irq(I_eof32)) {
        return goto_off();
    }

    _u.clear_bit_register8(REG_OPERATION_CONTROL, wu);  // Disable wakeup mode
    _u.writeModeDefinition(mode_listen_nfc_a);          // Disable birrate detection and collision
    _u.writeBitrate(_bitrate, _bitrate);

    return EmulationLayerA::State::Ready;
}

EmulationLayerA::State ListenerST25R3916ForA::goto_active()
{
    _data_flag = false;
    _u.set_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_106_ac_a);  // Disable auto response for NFC-A
    (void)get_irq(I_par32 | I_crc32 | I_err232 | I_err132);

    _u.enable_interrupts(I_rxe32);

    /*
    uint32_t m32{};
    _u.readMaskInterrupts(m32);
    M5_LIB_LOGE("M:%08X", m32);
    */

    return EmulationLayerA::State::Active;
}

EmulationLayerA::State ListenerST25R3916ForA::goto_halt()
{
    _data_flag = false;
    _u.clear_bit_register8(REG_NFCIP_1_PASSIVE_TARGET_DEFINITION, d_106_ac_a);  // Enable auto response for NFC-A
    _u.writeDirectCommand(CMD_GO_TO_SLEEP);

    _u.change_bit_register8(REG_MODE_DEFINITION, mode_bitrate_detection, mode_mask);
    _u.clear_bit_register8(REG_ISO14443A_SETTINGS, nfc_f0);

    //_u.writeDirectCommand(CMD_CLEAR_FIFO);
    _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);

    _u.enable_interrupts(I_nfct32 | I_rxs32 | I_crc32 | I_err132 | I_err232 | I_par32 | I_eon32 | I_eof32 | mode_irq);

    if (!is_extra_field()) {
        return goto_off();
    }
    return EmulationLayerA::State::Halt;
}

// ------------------------------------------------------------
EmulationLayerA::State ListenerST25R3916ForA::update_off()
{
    // IRQ due to detection of external field
    if ((get_irq(I_eon32) & I_eon32)) {
        return goto_idle();
    }
    return EmulationLayerA::State::Off;
}

EmulationLayerA::State ListenerST25R3916ForA::update_idle()
{
    uint32_t irq32 = get_irq(I_nfct32 | I_rxe32 | I_eof32 | I_rxe_pta);
    if (!irq32) {
        return EmulationLayerA::State::Idle;
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
        M5_LIB_LOGE("OFF");
        return goto_off();
    }
    if ((irq32 & I_rxe32) && _bitrate != Bitrate::Invalid) {
        irq32 |= get_irq(I_rxe32 | I_eof32 | I_crc32 | I_par32 | I_err232 | I_err132);
        if (irq32 & (I_crc32 | I_par32 | I_err132)) {
            M5_LIB_LOGE("   -> RECEIVE ERR %08X", irq32);
            _u.writeDirectCommand(CMD_CLEAR_FIFO);
            _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
            _u.clear_bit_register8(REG_OPERATION_CONTROL, tx_en);
            return EmulationLayerA::State::Idle;
        }
        M5_LIB_LOGE("   -> RECEIVE %08X", irq32);

        uint16_t bytes{};
        uint8_t bits{};
        uint8_t rx[64]{};
        uint16_t rx_len{}, actual{};
        _u.readFIFOSize(bytes, bits);
        rx_len = std::min<uint16_t>(bytes, sizeof(rx));
        _u.readFIFO(actual, rx, rx_len);

        // m5::utility::log::dump(rx, actual, false);

        if (actual > 2 && _bitrate == Bitrate::Bps106K) {
            m5::utility::CRC16 crc16(0xC6C6, 0x1021, true, true, 0);  // 0x6363
            auto crc = crc16.range(rx, actual);
            M5_LIB_LOGE("CRC:%04X", crc);
            if (crc) {
                _u.writeDirectCommand(CMD_CLEAR_FIFO);
                _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
                _u.clear_bit_register8(REG_OPERATION_CONTROL, tx_en);
                return EmulationLayerA::State::Idle;
            }
        }
        actual -= (actual > 2) ? 2 : actual;
        _receive_bits = actual << 3;
        _data_flag    = true;
        // rfalCheckDisableObsMode(); if obsMode rx -> obs Disable
        return EmulationLayerA::State::Idle;
    }
    if ((irq32 & I_rxe_pta32) && _bitrate == Bitrate::Bps106K) {
        uint8_t pta{};
        if (_u.readPassiveTargetDisplay(pta) && ((pta & 0x0F) > pta_state_idle)) {
            // M5_LIB_LOGE("PTA:%02X", pta);
            return goto_ready();
        }
        // M5_LIB_LOGE("PTA:%02X", pta);
    }

    return EmulationLayerA::State::Idle;
}

EmulationLayerA::State ListenerST25R3916ForA::update_ready()
{
    uint32_t irq32 = get_irq(I_eof32 | (_wakeup ? I_wu_ax32 : I_wu_a32));
    if (!irq32) {
        return EmulationLayerA::State::Ready;
    }

    if (is_eof(irq32)) {
        return goto_off();
    }
    if (irq32 & (I_wu_a32 | I_wu_ax32)) {
        return goto_active();
    }

    return EmulationLayerA::State::Ready;
}

EmulationLayerA::State ListenerST25R3916ForA::update_active()
{
    // uint32_t irq32 = get_irq(I_eof32 | I_rxe32 | I_par32 | I_crc32 | I_err232 | I_err132);
    uint32_t irq32 = get_irq(I_eof32 | I_rxe32);
    if (!irq32) {
        return EmulationLayerA::State::Active;
    }
    if (is_eof(irq32)) {
        return goto_off();
    }

    uint16_t bytes{};
    uint8_t bits{};
    uint16_t rx_len{}, actual{};
    uint8_t rx[64]{};
    if (irq32 & I_rxe32) {
        irq32 |= get_irq(I_par32 | I_crc32 | I_err232 | I_err132);
        _u.readFIFOSize(bytes, bits);
        rx_len = bytes;

        if (irq32 & (I_par32 | I_crc32 | I_err132 | I_err232) || rx_len <= 2) {
            _u.readFIFO(actual, rx, rx_len);
            M5_LIB_LOGE("A ERR %08X %u %u %02X", irq32, _wakeup, rx_len, rx[0]);

            _u.writeDirectCommand(CMD_CLEAR_FIFO);
            _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
            // return EmulationLayerA::State::Active;
            return _wakeup ? goto_halt() : goto_idle();
        }

        if (irq32 & I_rxe32) {
            rx_len -= 2;
            _u.readFIFO(actual, rx, rx_len);
            _data_flag = true;

            auto state = _layer.receive_callback(rx, rx_len);
            if (state != EmulationLayerA::State::Active) {
                if (state == EmulationLayerA::State::Idle && _wakeup) {
                    state = EmulationLayerA::State::Halt;
                }
                _u.disable_interrupts(I_rxe32);
                return goto_state(state);
            }
        }
    }
    return EmulationLayerA::State::Active;
}

EmulationLayerA::State ListenerST25R3916ForA::update_halt()
{
    auto irq32 = get_irq(I_nfct32 | I_rxe32 | I_eof32 | I_rxe_pta32);
    if (!irq32) {
        return EmulationLayerA::State::Halt;
    }

    static uint32_t latest = 0;
    if (latest != irq32) {
        latest = irq32;
    }

    // initiator bit rate was recognized
    if ((irq32 & I_nfct32) && _bitrate == Bitrate::Invalid) {
        uint8_t br{};
        _u.readBitrateDetectionDisplay(br);
        br = (br >> 4) & 0x03;  // 0:106 1:212 2:424 3:848
        if (br > 2) {
            br = 2;
        }
        _bitrate = static_cast<Bitrate>(br);
    }
    if (is_eof(irq32)) {
        return goto_off();
    }
    if ((irq32 & I_rxe32) && _bitrate != Bitrate::Invalid) {
        _u.writeDirectCommand(CMD_CLEAR_FIFO);
        _u.writeDirectCommand(CMD_UNMASK_RECEIVE_DATA);
        return EmulationLayerA::State::Halt;
    }
    if ((irq32 & I_rxe_pta32) && _bitrate == Bitrate::Bps106K) {
        uint8_t pta{};
        if (_u.readPassiveTargetDisplay(pta) && ((pta & 0x0F) > pta_state_halt)) {
            _wakeup = true;
            return goto_ready();
        }
    }
    return EmulationLayerA::State::Halt;
}

bool ListenerST25R3916ForA::is_extra_field()
{
    uint8_t v{};
    return _u.readAuxiliaryDisplay(v) && (v & efd_o);
}

//
namespace {
std::unique_ptr<EmulationLayerA::Adapter> make_st25r3916_adapter(EmulationLayerA& l, UnitST25R3916& u)
{
    return std::unique_ptr<EmulationLayerA::Adapter>(new ListenerST25R3916ForA(l, u));
}
}  // namespace

EmulationLayerA::EmulationLayerA(UnitST25R3916& u) : _impl(make_st25r3916_adapter(*this, u))
{
}

EmulationLayerA::EmulationLayerA(CapST25R3916& u) : _impl(make_st25r3916_adapter(*this, static_cast<UnitST25R3916&>(u)))
{
}

}  // namespace nfc
}  // namespace m5
