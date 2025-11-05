/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a_ST25R3916.cpp
  @brief ST25R3916 adapter for common layer
*/
#include <nfc/layer/nfc_layer_a.hpp>
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
struct AdapterST25R3916 final : NFCLayerA::Adapter {
    explicit AdapterST25R3916(UnitST25R3916& ref) : _u{ref}
    {
    }

    virtual bool detect(std::vector<UID>& devs, const uint32_t timeout_ms) override;
    virtual bool activate(const UID& uid) override;
    virtual bool deactivate() override;
    virtual bool mifare_authenticate(const m5::nfc::a::Command cmd, const UID& uid, const uint8_t block,
                                     const Key& key) override;
    virtual bool readBlock(uint8_t* rx, uint16_t& rx_len, const uint16_t addr) override;
    virtual bool writeBlock(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len) override;

    UnitST25R3916& _u;
};

bool AdapterST25R3916::detect(std::vector<UID>& devs, const uint32_t timeout_ms)
{
    devs.clear();

    auto timeout_at = m5::utility::millis() + timeout_ms;
    UID uid{};

    uint16_t atqa{};
    do {
        // Exists devices?
        if (!_u.nfcaRequest(atqa)) {
            break;
        }

        // Select
        uint8_t lv{1};  // Cascade level 1-3
        bool completed{};
        uid.clear();
        do {
            if (!_u.nfcaSelectWithAnticollision(completed, uid, lv)) {
                return false;
            }
        } while (!completed && lv++ < 4);
        if (!completed) {
            return false;
        }
        M5_LIB_LOGD("Detect:%s", uid.uidAsString().c_str());

        // Type identification
        uid.type   = _u.nfca_identify_type(uid);
        uid.blocks = get_number_of_blocks(uid.type);
        _activeUID = uid;

        // Deactive(HltA)
        if (!deactivate()) {
            M5_LIB_LOGD("Failed to deactivate");
            return false;
        }

        push_back_uid(devs, uid);

    } while (m5::utility::millis() <= timeout_at);

    return !devs.empty();
}

bool AdapterST25R3916::activate(const UID& uid)
{
    uint16_t atqa{};
    _activeUID.clear();
    if (_u.nfcaWakeup(atqa) && _u.nfcaSelect(uid)) {
        M5_LIB_LOGD("Activate:%s", uid.uidAsString().c_str());
        _activeUID = uid;
        return true;
    }
    return false;
}

bool AdapterST25R3916::deactivate()
{
    M5_LIB_LOGD("Deactivate:%s", _activeUID.uidAsString().c_str());
    _activeUID.clear();
    return _u.nfcaHlt();
}

bool AdapterST25R3916::mifare_authenticate(const m5::nfc::a::Command cmd, const UID& uid, const uint8_t block,
                                           const Key& key)
{
    return _u.mifare_classic_authenticate(cmd, uid, block, key);
}

bool AdapterST25R3916::readBlock(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)
{
    return _activeUID.isClassic() ? _u.mifareClassicReadBlock(rx, rx_len, addr) : _u.nfcaReadBlock(rx, rx_len, addr);
}

bool AdapterST25R3916::writeBlock(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len)
{
    return true;
}

//
namespace {
std::unique_ptr<NFCLayerA::Adapter> make_st25r3916_adapter(UnitST25R3916& u)
{
    return std::unique_ptr<NFCLayerA::Adapter>(new AdapterST25R3916(u));
}
}  // namespace

NFCLayerA::NFCLayerA(UnitST25R3916& u) : _impl(make_st25r3916_adapter(u))
{
}

NFCLayerA::NFCLayerA(CapST25R3916& u) : _impl(make_st25r3916_adapter(static_cast<UnitST25R3916&>(u)))
{
}

}  // namespace nfc
}  // namespace unit
}  // namespace m5
