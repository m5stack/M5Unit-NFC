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
namespace unit {
namespace nfc {

//
struct AdapterST25R3916ForF final : NFCLayerF::Adapter {
    explicit AdapterST25R3916ForF(UnitST25R3916& ref) : _u{ref}
    {
    }

    virtual bool polling(m5::nfc::f::PICC& picc, const uint16_t system_code, const m5::nfc::f::RequestCode request_code,
                         const m5::nfc::f::TimeSlot time_slot) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForF::polling(m5::nfc::f::PICC& picc, const uint16_t system_code,
                                   const m5::nfc::f::RequestCode request_code, const m5::nfc::f::TimeSlot time_slot)
{
    return _u.nfcfPolling(picc, system_code, request_code, time_slot);
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
}  // namespace unit
}  // namespace m5
