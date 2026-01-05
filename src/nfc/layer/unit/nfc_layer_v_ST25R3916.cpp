/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_v_ST25R3916.cpp
  @brief ST25R3916 NFC-V adapter for common layer
*/
#include "nfc/layer/nfc_layer_v.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "unit/unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::unit;
using namespace m5::unit::st25r3916;
using namespace m5::nfc::f;

namespace m5 {
namespace nfc {

//
struct AdapterST25R3916ForV final : NFCLayerV::Adapter {
    explicit AdapterST25R3916ForV(UnitST25R3916& ref) : _u{ref}
    {
    }

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms, const m5::nfc::v::ModulationMode mode) override;
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms,
                          const m5::nfc::v::ModulationMode mode) override;
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForV::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                      const uint32_t timeout_ms, const m5::nfc::v::ModulationMode mode)
{
    return _u.nfcvTransceive(rx, rx_len, tx, tx_len, timeout_ms, mode);
}

bool AdapterST25R3916ForV::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms,
                                    const m5::nfc::v::ModulationMode mode)
{
    return _u.nfcvTransmit(tx, tx_len, timeout_ms, mode);
}

bool AdapterST25R3916ForV::receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    return _u.nfcvReceive(rx, rx_len, timeout_ms);
}

//
namespace {
std::unique_ptr<NFCLayerV::Adapter> make_st25r3916_adapter(UnitST25R3916& u)
{
    return std::unique_ptr<NFCLayerV::Adapter>(new AdapterST25R3916ForV(u));
}
}  // namespace

NFCLayerV::NFCLayerV(UnitST25R3916& u) : _impl(make_st25r3916_adapter(u)), _ndef{*this}
{
}

NFCLayerV::NFCLayerV(CapST25R3916& u) : _impl(make_st25r3916_adapter(static_cast<UnitST25R3916&>(u))), _ndef{*this}
{
}

}  // namespace nfc
}  // namespace m5
