/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_f_ST25R3916.cpp
  @brief ST25R3916 NFC-F adapter for common layer
*/
#include "nfc/layer/nfc_layer_f.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "unit/unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::unit;
using namespace m5::unit::st25r3916;
using namespace m5::nfc::f;

namespace m5 {
namespace nfc {

//
struct AdapterST25R3916ForF final : NFCLayerF::Adapter {
    explicit AdapterST25R3916ForF(UnitST25R3916& ref) : _u{ref}
    {
    }

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForF::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                      const uint32_t timeout_ms)
{
    return _u.nfcfTransceive(rx, rx_len, tx, tx_len, timeout_ms);
}

//
namespace {
std::unique_ptr<NFCLayerF::Adapter> make_st25r3916_adapter(UnitST25R3916& u)
{
    return std::unique_ptr<NFCLayerF::Adapter>(new AdapterST25R3916ForF(u));
}
}  // namespace

NFCLayerF::NFCLayerF(UnitST25R3916& u) : _impl(make_st25r3916_adapter(u)), _ndef{*this}
{
}

NFCLayerF::NFCLayerF(CapST25R3916& u) : _impl(make_st25r3916_adapter(static_cast<UnitST25R3916&>(u))), _ndef{*this}
{
}

}  // namespace nfc
}  // namespace m5
