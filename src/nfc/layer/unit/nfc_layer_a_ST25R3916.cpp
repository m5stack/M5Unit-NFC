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

    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) override;

    virtual bool request(uint16_t& atqa) override;
    virtual bool wakeup(uint16_t& atqa) override;

    virtual bool select(m5::nfc::a::PICC& picc) override;
    virtual bool activate(const m5::nfc::a::PICC& picc) override;
    virtual bool deactivate(const bool iso14443_4) override;

    virtual bool nfca_request_ats(m5::nfc::a::ATS& ats) override;
    virtual bool nfca_read_block(uint8_t rx[16], const uint8_t addr) override;         // READ
    virtual bool nfca_write_block(const uint8_t addr, const uint8_t tx[16]) override;  // WRITE_BLOCK
    virtual bool nfca_write_page(const uint8_t addr, const uint8_t tx[4]) override;    // WRITE_PAGE

    virtual bool mifare_classic_authenticate(const bool auth_a, const m5::nfc::a::PICC& picc, const uint8_t block,
                                             const m5::nfc::a::mifare::classic::Key& key) override;
    virtual bool mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block,
                                            const uint32_t arg = 0) override;
    virtual bool mifare_ultralightC_authenticate1(uint8_t ek[8]) override;
    virtual bool mifare_ultralightC_authenticate2(uint8_t rx_ek[8], const uint8_t tx_ek[16]) override;
    virtual bool mifare_get_version_L3(uint8_t ver[8]) override;
    virtual bool mifare_get_version_L4(uint8_t ver[8]) override;
    virtual bool mifare_ultralightc_authenticate1(uint8_t ek[8]) override;

    virtual bool ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage,
                                const uint8_t epage) override;  // FAST_READ

    UnitST25R3916& _u;
};

bool AdapterST25R3916ForA::transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                                      const uint32_t timeout_ms)
{
    return _u.nfcaTransceive(rx, rx_len, tx, tx_len, timeout_ms);
}

bool AdapterST25R3916ForA::request(uint16_t& atqa)
{
    return _u.nfcaRequest(atqa);
}

bool AdapterST25R3916ForA::wakeup(uint16_t& atqa)
{
    return _u.nfcaWakeup(atqa);
}

bool AdapterST25R3916ForA::select(m5::nfc::a::PICC& picc)
{
    uint8_t lv{1};  // Cascade level 1-3
    bool completed{};
    auto atqa = picc.atqa;
    picc      = PICC{};
    picc.atqa = atqa;
    do {
        if (!_u.nfcaSelectWithAnticollision(completed, picc, lv)) {
            return false;
        }
    } while (!completed && lv++ < 4);
    return completed;
}

bool AdapterST25R3916ForA::activate(const PICC& picc)
{
    return _u.nfcaSelect(picc);
}

bool AdapterST25R3916ForA::deactivate(const bool iso14443_4)
{
    return iso14443_4 ? _u.nfcaDeselect() : _u.nfcaHlt();
}

bool AdapterST25R3916ForA::nfca_request_ats(m5::nfc::a::ATS& ats)
{
    return _u.nfcaRequestATS(ats);
}

bool AdapterST25R3916ForA::nfca_read_block(uint8_t rx[16], const uint8_t addr)
{
    return _u.nfcaReadBlock(rx, addr);
}

bool AdapterST25R3916ForA::nfca_write_block(const uint8_t addr, const uint8_t tx[16])
{
    return _u.nfcaWriteBlock(addr, tx);
}

bool AdapterST25R3916ForA::nfca_write_page(const uint8_t addr, const uint8_t tx[4])
{
    return _u.nfcaWritePage(addr, tx);
}

bool AdapterST25R3916ForA::mifare_classic_authenticate(const bool auth_a, const PICC& picc, const uint8_t block,
                                                       const Key& key)
{
    return auth_a ? _u.mifareClassicAuthenticateA(picc, block, key) : _u.mifareClassicAuthenticateB(picc, block, key);
}

bool AdapterST25R3916ForA::mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block,
                                                      const uint32_t arg)
{
    return _u.mifareClassicValueBlock(cmd, block, arg);
}

bool AdapterST25R3916ForA::mifare_ultralightC_authenticate1(uint8_t ek[8])
{
    return _u.mifareUltralightCAuthenticate1(ek);
}

bool AdapterST25R3916ForA::mifare_ultralightC_authenticate2(uint8_t rx_ek[8], const uint8_t tx_ek[16])
{
    return _u.mifareUltralightCAuthenticate2(rx_ek, tx_ek);
}

bool AdapterST25R3916ForA::mifare_get_version_L3(uint8_t ver[8])
{
    return _u.mifareGetVersion3(ver);
}

bool AdapterST25R3916ForA::mifare_get_version_L4(uint8_t ver[8])
{
    return _u.mifareGetVersion4(ver);
}

bool AdapterST25R3916ForA::mifare_ultralightc_authenticate1(uint8_t ek[8])
{
    return _u.mifareUltralightCAuthenticate1(ek);
}

bool AdapterST25R3916ForA::ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage)
{
    return _u.ntagReadPage(rx, rx_len, spage, epage);
}

//
namespace {
std::unique_ptr<NFCLayerA::Adapter> make_st25r3916_adapter(UnitST25R3916& u)
{
    return std::unique_ptr<NFCLayerA::Adapter>(new AdapterST25R3916ForA(u));
}
}  // namespace

NFCLayerA::NFCLayerA(UnitST25R3916& u) : _ndef{*this}, _isoDEP{*this}, _impl(make_st25r3916_adapter(u))
{
}

NFCLayerA::NFCLayerA(CapST25R3916& u)
    : _ndef{*this}, _isoDEP(*this), _impl(make_st25r3916_adapter(static_cast<UnitST25R3916&>(u)))
{
}

}  // namespace nfc
}  // namespace m5
