/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_b_ST25R3916.cpp
  @brief ST25R3916 NFC-B adapter for common layer
*/
#include "nfc/layer/b/nfc_layer_b.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "unit/unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::unit;
using namespace m5::unit::st25r3916;
using namespace m5::nfc::b;

namespace m5 {
namespace nfc {

//
struct AdapterST25R3916ForB final : NFCLayerB::Adapter {
    explicit AdapterST25R3916ForB(UnitST25R3916& ref) : _u{ref}
    {
    }
    inline virtual uint16_t max_fifo_depth() const override
    {
        return m5::unit::st25r3916::MAX_FIFO_DEPTH;
    }

    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                    const uint32_t timeout_ms) override;
    bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) override;
    bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForB::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                      const uint32_t timeout_ms)
{
    return _u.nfcbTransceive(rx, rx_len, tx, tx_len, timeout_ms);
}

bool AdapterST25R3916ForB::transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)

{
    return _u.nfcbTransmit(tx, tx_len, timeout_ms);
}

bool AdapterST25R3916ForB::receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
{
    return _u.nfcbReceive(rx, rx_len, timeout_ms);
}

//
namespace {
std::unique_ptr<NFCLayerB::Adapter> make_st25r3916_adapter(UnitST25R3916& u)
{
    return std::unique_ptr<NFCLayerB::Adapter>(new AdapterST25R3916ForB(u));
}
}  // namespace

NFCLayerB::NFCLayerB(UnitST25R3916& u) : _ndef{*this}, _isoDEP{*this}, _impl(make_st25r3916_adapter(u))
{
}

NFCLayerB::NFCLayerB(CapST25R3916& u)
    : _ndef{*this}, _isoDEP{*this}, _impl(make_st25r3916_adapter(static_cast<UnitST25R3916&>(u)))
{
}

}  // namespace nfc
}  // namespace m5
