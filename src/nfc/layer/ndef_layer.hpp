/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file ndef_layer.hpp
  @brief Common layer for NDEF related
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NDEF_LAYER_HPP
#define M5_UNIT_NFC_NFC_LAYER_NDEF_LAYER_HPP

#include "nfc_layer.hpp"
#include "nfc/ndef/ndef.hpp"
#include <vector>

namespace m5 {
namespace nfc {
class NFCLayerInterface;
namespace isodep {
class IsoDEP;
}
namespace ndef {

class TLV;
class Record;

constexpr uint8_t NDEF_MAX_UNIT_SIZE_READ{32};
constexpr uint8_t NDEF_MAX_CC_BLOCK_SIZE{32};

/*!
  @class NDEFLayer
  @brief NDEF operations layer
 */
class NDEFLayer {
public:
    explicit NDEFLayer(NFCLayerInterface& layer) : _interface{layer}
    {
    }
    /*!
      @brief Check whether the tag is in NDEF format
      @param[out] valid True if the tag has a valid NDEF format
      @param ftag NFC Forum Tag type
      @return True if command succeeded
     */
    bool isValidFormat(bool& valid, const m5::nfc::NFCForumTag ftag);

    /*!
      @brief Read NDEF data
      @param ftag NFC Forum Tag type
      @param[out] tlvs Output TLVs
      @param tagBits Target TLV tags
      @return True if successful
     */
    bool read(const m5::nfc::NFCForumTag ftag, std::vector<m5::nfc::ndef::TLV>& tlvs,
              const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsMessage);
    /*!
      @brief Write NDEF data
      @param ftag NFC Forum Tag type
      @param tlvs TLVs to write
      @param keep Keep existing TLVs when possible
      @return True if successful
      @note The message will be overwritten
     */
    bool write(const m5::nfc::NFCForumTag ftag, const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep = true);

    /*!
      @brief Prepare NDEF files on MIFARE DESFire Light
      @return True if successful
     */
    bool prepare_desfire_light();
    /*!
      @brief Prepare NDEF files on MIFARE DESFire (EV1/EV2/EV3)
      @param max_ndef_size Max size for NDEF file
      @return True if successful
     */
    bool prepare_desfire(const uint32_t max_ndef_size);

    /*!
      @brief Read Type2 Capability Container
      @param[out] cc Capability container
      @return True if successful
     */
    bool readCapabilityContainer(m5::nfc::ndef::type2::CapabilityContainer& cc);
    /*!
      @brief Read Type3 Attribute Block
      @param[out] ab Attribute block
      @return True if successful
     */
    bool readAttributeBlock(m5::nfc::ndef::type3::AttributeBlock& ab);
    /*!
      @brief Read Type4 Capability Container
      @param[out] cc Capability container
      @return True if successful
     */
    bool readCapabilityContainer(m5::nfc::ndef::type4::CapabilityContainer& cc);
    /*!
      @brief Read Type5 Capability Container
      @param[out] cc Capability container
      @return True if successful
     */
    bool readCapabilityContainer(m5::nfc::ndef::type5::CapabilityContainer& cc);
    /*!
      @brief Write Type5 Capability Container
      @param[in] cc Capability container
      @return True if successful
     */
    bool writeCapabilityContainer(const m5::nfc::ndef::type5::CapabilityContainer& cc);

protected:
    bool read_capability_container_type4_iso7816(m5::nfc::ndef::type4::CapabilityContainer& cc);
    bool read_capability_container_type4_desfire(m5::nfc::ndef::type4::CapabilityContainer& cc);

    bool read_type2(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits);
    bool read_type3(m5::nfc::ndef::TLV& tlv);
    bool read_type4(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::type4::FileControlTagBits fcBits);
    bool read_type4_iso7816(std::vector<m5::nfc::ndef::TLV>& tlvs,
                            const m5::nfc::ndef::type4::FileControlTagBits fcBits);
    bool read_type4_desfire(std::vector<m5::nfc::ndef::TLV>& tlvs,
                            const m5::nfc::ndef::type4::FileControlTagBits fcBits);
    bool read_type5(std::vector<m5::nfc::ndef::TLV>& tlvs, const m5::nfc::ndef::TagBits tagBits);

    bool write_type2(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep);
    bool write_type3(const m5::nfc::ndef::TLV& tlv);
    bool write_type4(const std::vector<m5::nfc::ndef::TLV>& tlvs);
    bool write_type4_iso7816(const std::vector<m5::nfc::ndef::TLV>& tlvs, const type4::CapabilityContainer& cc,
                             isodep::IsoDEP& dep);
    bool write_type4_desfire(const std::vector<m5::nfc::ndef::TLV>& tlvs, const type4::CapabilityContainer& cc,
                             isodep::IsoDEP& dep);
    bool write_type5(const std::vector<m5::nfc::ndef::TLV>& tlvs, const bool keep);

    std::vector<m5::nfc::ndef::TLV> merge_tlv(std::vector<m5::nfc::ndef::TLV>& old_tlvs,
                                              const std::vector<m5::nfc::ndef::TLV>& tlvs);

    ///@name Byte-level access helpers for NFC-V (Type5)
    ///@{
    /*!
      @brief Read bytes from arbitrary byte offset (for NFC-V)
      @param[out] rx Output buffer
      @param offset Byte offset from start of user area
      @param len Number of bytes to read
      @return True if successful
     */
    bool read_nfcv(uint8_t* rx, const uint16_t offset, const uint16_t len);
    /*!
      @brief Write bytes to arbitrary byte offset (for NFC-V)
      @param offset Byte offset from start of user area
      @param tx Input buffer
      @param len Number of bytes to write
      @return True if successful
      @note Performs read-modify-write for partial block writes
     */
    bool write_nfcv(const uint16_t offset, const uint8_t* tx, const uint16_t len);
    ///@}

private:
    NFCLayerInterface& _interface;
};

}  // namespace ndef
}  // namespace nfc
}  // namespace m5

#endif
