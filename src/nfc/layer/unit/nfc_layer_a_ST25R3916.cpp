/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a_ST25R3916.cpp
  @brief ST25R3916 NFC-A adapter for common layer
*/
#include "nfc/layer/nfc_layer_a.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "unit/unit_ST25R3916.hpp"
#include <M5Utility.hpp>

using namespace m5::unit;
using namespace m5::unit::st25r3916;
using namespace m5::nfc::a;
using namespace m5::nfc::a::mifare;
using namespace m5::nfc::a::mifare::classic;

namespace m5 {
namespace unit {
namespace nfc {
//
struct AdapterST25R3916ForA final : NFCLayerA::Adapter {
    explicit AdapterST25R3916ForA(UnitST25R3916& ref) : _u{ref}
    {
    }

    inline virtual uint16_t max_fifo_depth() override
    {
        return m5::unit::st25r3916::MAX_FIFO_DEPTH;
    }

    virtual bool request(uint16_t& atqa) override;
    virtual bool wakeup(uint16_t& atqa) override;

    virtual bool select(m5::nfc::a::UID& uid) override;
    virtual bool activate(const m5::nfc::a::UID& uid) override;
    virtual bool deactivate() override;

    virtual bool nfca_read_block(uint8_t rx[16], const uint8_t addr) override;         // READ
    virtual bool nfca_write_block(const uint8_t addr, const uint8_t tx[16]) override;  // WRITE_BLOCK
    virtual bool nfca_write_page(const uint8_t addr, const uint8_t tx[4]) override;    // WRITE_PAGE

    virtual bool mifare_classic_authenticate(const bool auth_a, const m5::nfc::a::UID& uid, const uint8_t block,
                                             const m5::nfc::a::mifare::classic::Key& key) override;
    virtual bool mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block,
                                            const uint32_t arg = 0) override;

    virtual bool ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage,
                                const uint8_t epage) override;  // FAST_READ

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForA::request(uint16_t& atqa)
{
    return _u.nfcaRequest(atqa);
}

bool AdapterST25R3916ForA::wakeup(uint16_t& atqa)
{
    return _u.nfcaWakeup(atqa);
}

bool AdapterST25R3916ForA::select(m5::nfc::a::UID& uid)
{
    uint8_t lv{1};  // Cascade level 1-3
    bool completed{};
    uid.clear();
    do {
        if (!_u.nfcaSelectWithAnticollision(completed, uid, lv)) {
            return false;
        }
    } while (!completed && lv++ < 4);
    return completed;
}

bool AdapterST25R3916ForA::activate(const UID& uid)
{
    return _u.nfcaSelect(uid);
}

bool AdapterST25R3916ForA::deactivate()
{
    return _u.nfcaHlt();
}

bool AdapterST25R3916ForA::nfca_read_block(uint8_t rx[16], const uint8_t addr)
{
    return _u.nfcaReadBlock(rx, addr);
}

bool AdapterST25R3916ForA::nfca_write_block(const uint8_t addr, const uint8_t tx[16])
{
    return _u.nfcaWriteBlock(addr, tx);
}

bool AdapterST25R3916ForA::ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage)
{
    return _u.ntagReadPage(rx, rx_len, spage, epage);
}

bool AdapterST25R3916ForA::nfca_write_page(const uint8_t addr, const uint8_t tx[4])
{
    return _u.nfcaWritePage(addr, tx);
}

bool AdapterST25R3916ForA::mifare_classic_authenticate(const bool auth_a, const UID& uid, const uint8_t block,
                                                       const Key& key)
{
    return auth_a ? _u.mifareClassicAuthenticateA(uid, block, key) : _u.mifareClassicAuthenticateB(uid, block, key);
}

bool AdapterST25R3916ForA::mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block,
                                                      const uint32_t arg)
{
    return _u.mifareClassicValueBlock(cmd, block, arg);
}

//
namespace {
std::unique_ptr<NFCLayerA::Adapter> make_st25r3916_adapter(UnitST25R3916& u)
{
    return std::unique_ptr<NFCLayerA::Adapter>(new AdapterST25R3916ForA(u));
}
}  // namespace

NFCLayerA::NFCLayerA(UnitST25R3916& u) : _impl(make_st25r3916_adapter(u)), _ndef{*this}
{
}

NFCLayerA::NFCLayerA(CapST25R3916& u) : _impl(make_st25r3916_adapter(static_cast<UnitST25R3916&>(u))), _ndef{*this}
{
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
