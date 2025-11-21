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
// #include "nfc/ndef/ndef.hpp"
#include <vector>

namespace m5 {
namespace nfc {
class NFCLayerInterface;
namespace ndef {

class Message;
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
    bool isValidFormat(bool& valid);
    bool readMessageSize(uint32_t& size, const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsAll);
    bool read(std::vector<m5::nfc::ndef::Message>& msgs,
              const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsNDEFMessage);
    bool write(const std::vector<m5::nfc::ndef::Message>& msgs);

protected:
    bool calculate_ndef_size(uint32_t& size, const uint8_t* p, const uint8_t* end, const uint8_t targetTagBit);

private:
    NFCLayerInterface& _interface;
};

}  // namespace ndef
}  // namespace nfc
}  // namespace m5

#endif
