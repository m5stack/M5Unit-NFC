/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_layer.hpp
  @brief Common layer for NDEF related
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NDEFC_LAYER_HPP
#define M5_UNIT_NFC_NFC_LAYER_NDEFC_LAYER_HPP

#include "nfc_layer.hpp"
#include "nfc/ndef/ndef.hpp"
#include <vector>

namespace m5 {
namespace nfc {
class NFCLayerInterface;
namespace ndef {

class TLV;
class Record;

/*!
  @class NDEFLayer
  @brief NDEF operations layer
 */
class NDEFLayer {
public:
    explicit NDEFLayer(NFCLayerInterface& layer) : _interface{layer}
    {
    }
    bool isValidFormat(const m5::nfc::NFCForumTag ftag, bool& valid);
    bool read(const m5::nfc::NFCForumTag ftag, std::vector<m5::nfc::ndef::TLV>& tlvs,
              const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsMessage);
    bool write(const m5::nfc::NFCForumTag ftag, const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep = true);

    // bool readTLVSize(uint32_t& size, const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsAll);

protected:
    bool read_with_tlv(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits);
    bool write_with_tlv(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep);

    bool read_without_tlv(m5::nfc::ndef::TLV& tlv);
    bool write_without_tlv(const m5::nfc::ndef::TLV& tlv);

    // bool calculate_ndef_size(uint32_t& size, const uint8_t* p, const uint8_t* end, const uint8_t targetTagBit);

private:
    NFCLayerInterface& _interface;
};

}  // namespace ndef
}  // namespace nfc
}  // namespace m5

#endif
