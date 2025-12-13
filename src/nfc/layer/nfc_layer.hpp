/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer.hpp
  @brief Common layer for NFC related units
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_HPP

#include "nfc/nfc.hpp"

namespace m5 {
namespace nfc {

class NFCLayerInterface {
public:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr)             = 0;
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) = 0;

    virtual uint16_t first_user_block() const = 0;
    virtual uint16_t last_user_block() const  = 0;
    virtual uint16_t user_area_size() const   = 0;
    virtual uint16_t unit_size_read() const   = 0;
    virtual uint16_t unit_size_write() const  = 0;

    // For NFC-F
    virtual uint8_t maximum_read_blocks() const
    {
        return 0;
    }
    virtual uint8_t maximum_write_blocks() const
    {
        return 0;
    }
};

}  // namespace nfc
}  // namespace m5
#endif
