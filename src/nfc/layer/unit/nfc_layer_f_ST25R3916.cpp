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

    virtual bool requestService(uint16_t key_version[], const m5::nfc::f::PICC& picc, const uint16_t* node_code,
                                const uint8_t node_num) override;
    virtual bool requestResponse(m5::nfc::f::standard::Mode& mode, const m5::nfc::f::PICC& picc) override;
    virtual bool requestSystemCode(uint16_t code_list[255], uint8_t& code_num, const m5::nfc::f::PICC& picc) override;

    virtual bool readWithoutEncryption(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::PICC& picc,
                                       const uint16_t* service_code, const uint8_t service_num,
                                       const block_t* block_list, const uint8_t block_num) override;
    virtual bool writeWithoutEncryption(const m5::nfc::f::PICC& picc, const uint16_t* service_code,
                                        const uint8_t service_num, const m5::nfc::f::block_t* block_list,
                                        const uint8_t block_num, const uint8_t* tx, const uint16_t tx_len) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForF::polling(m5::nfc::f::PICC& picc, const uint16_t system_code,
                                   const m5::nfc::f::RequestCode request_code, const m5::nfc::f::TimeSlot time_slot)
{
    return _u.nfcfPolling(picc, system_code, request_code, time_slot);
}

bool AdapterST25R3916ForF::requestService(uint16_t key_version[], const m5::nfc::f::PICC& picc,
                                          const uint16_t* node_code, const uint8_t node_num)
{
    return _u.nfcfRequestService(key_version, picc, node_code, node_num);
}

bool AdapterST25R3916ForF::requestResponse(m5::nfc::f::standard::Mode& mode, const m5::nfc::f::PICC& picc)
{
    return _u.nfcfRequestResponse(mode, picc);
}

bool AdapterST25R3916ForF::requestSystemCode(uint16_t code_list[255], uint8_t& code_num, const m5::nfc::f::PICC& picc)
{
    return _u.nfcfRequestSystemCode(code_list, code_num, picc);
}

bool AdapterST25R3916ForF::readWithoutEncryption(uint8_t* rx, uint16_t& rx_len, const m5::nfc::f::PICC& picc,
                                                 const uint16_t* service_code, const uint8_t service_num,
                                                 const block_t* block_list, const uint8_t block_size)
{
    return _u.nfcfReadWithoutEncryption(rx, rx_len, picc, service_code, service_num, block_list, block_size);
}

bool AdapterST25R3916ForF::writeWithoutEncryption(const m5::nfc::f::PICC& picc, const uint16_t* service_code,
                                                  const uint8_t service_num, const m5::nfc::f::block_t* block_list,
                                                  const uint8_t block_num, const uint8_t* tx, const uint16_t tx_len)
{
    return _u.nfcfWriteWithoutEncryption(picc, service_code, service_num, block_list, block_num, tx, tx_len);
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
