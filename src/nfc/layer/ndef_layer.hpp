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
    bool isValidFormat(bool& valid, const m5::nfc::NFCForumTag ftag);

    bool read(const m5::nfc::NFCForumTag ftag, std::vector<m5::nfc::ndef::TLV>& tlvs,
              const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsMessage);
    bool write(const m5::nfc::NFCForumTag ftag, const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep = true);

    bool readCapabilityContainer(m5::nfc::ndef::type2::CapabilityContainer& cc);
    bool readAttributeBlock(m5::nfc::ndef::type3::AttributeBlock& ab);
    bool readCapabilityContainer(m5::nfc::ndef::type4::CapabilityContainer& cc);
    bool readCapabilityContainer(m5::nfc::ndef::type5::CapabilityContainer& cc);

protected:
    bool read_type2(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits);
    bool read_type3(m5::nfc::ndef::TLV& tlv);
    bool read_type4(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::type4::FileControlTagBits fcBits);
    bool read_type5(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits);

    bool write_type2(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep);
    bool write_type3(const m5::nfc::ndef::TLV& tlv);
    bool write_type5(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep);

    std::vector<m5::nfc::ndef::TLV> merge_tlv(std::vector<m5::nfc::ndef::TLV>& old_tlvs,
                                              const std::vector<m5::nfc::ndef::TLV>& tlvs);

private:
    NFCLayerInterface& _interface;
};

}  // namespace ndef
}  // namespace nfc
}  // namespace m5

#endif
