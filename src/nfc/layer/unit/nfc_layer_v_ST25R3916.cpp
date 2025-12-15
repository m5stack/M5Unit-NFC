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
namespace unit {
namespace nfc {

//
struct AdapterST25R3916ForV final : NFCLayerV::Adapter {
    explicit AdapterST25R3916ForV(UnitST25R3916& ref) : _u{ref}
    {
    }

    virtual bool inventory(std::vector<m5::nfc::v::PICC>& piccs) override;
    virtual bool stay_quiet(const m5::nfc::v::PICC& picc) override;
    virtual bool select(const m5::nfc::v::PICC& picc) override;
    virtual bool reset_to_ready() override;
    virtual bool reset_to_ready(const m5::nfc::v::PICC& picc) override;
    virtual bool get_system_information(m5::nfc::v::PICC& picc) override;
    virtual bool read_single_block(uint8_t rx[32], const uint8_t block) override;
    virtual bool write_single_block(const uint8_t block, const uint8_t* tx, const uint8_t tx_len,
                                    const bool opt) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForV::inventory(std::vector<m5::nfc::v::PICC>& piccs)
{
    return _u.nfcvInventry(piccs, true);
}

bool AdapterST25R3916ForV::stay_quiet(const m5::nfc::v::PICC& picc)
{
    return _u.nfcvStayQuiet(picc);
}

bool AdapterST25R3916ForV::select(const m5::nfc::v::PICC& picc)
{
    return _u.nfcvSelect(picc);
}

bool AdapterST25R3916ForV::reset_to_ready(const m5::nfc::v::PICC& picc)
{
    return _u.nfcvResetToReady(picc);
}

bool AdapterST25R3916ForV::reset_to_ready()
{
    return _u.nfcvResetToReady();
}

bool AdapterST25R3916ForV::get_system_information(m5::nfc::v::PICC& picc)
{
    return _u.nfcvGetSystemInformation(picc);
}

bool AdapterST25R3916ForV::read_single_block(uint8_t rx[32], const uint8_t block)
{
    return _u.nfcvReadSingleBlock(rx, block);
}

bool AdapterST25R3916ForV::write_single_block(const uint8_t block, const uint8_t* tx, const uint8_t tx_len,
                                              const bool opt)
{
    return _u.nfcvWriteSingleBlock(block, tx, tx_len, opt);
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
}  // namespace unit
}  // namespace m5
