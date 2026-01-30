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

namespace isodep {
class IsoDEP;
}

/*!
  @class NFCLayerInterface
  @brief Common interface for NFC layer
 */
class NFCLayerInterface {
public:
    //! @brief activePICC's NDEF type
    virtual m5::nfc::NFCForumTag supportsNFCTag() const
    {
        return m5::nfc::NFCForumTag::None;
    }
    //! @brief activePICC's File system
    virtual file_system_feature_t supportsFilesystem() const
    {
        return file_system_feature_t(0);
    }
    //! @brief ISO-DEP interface (nullptr if not supported)
    virtual m5::nfc::isodep::IsoDEP* isoDEP()
    {
        return nullptr;
    }
    //! @brief Maximum FIFO depth
    virtual uint16_t maximum_fifo_depth() const = 0;

    //! @brief Transceive (RF command)
    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms)
    {
        return false;
    }

    //! @brief Transmit only
    virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms)
    {
        return false;
    }
    //! @brief Receive only
    virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms)
    {
        return false;
    }

    //! @brief Read NDEF (block)
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint16_t saddr) = 0;
    //! @brief Write NDEF (block)
    virtual bool write(const uint16_t saddr, const uint8_t* tx, const uint16_t tx_len) = 0;

    //! @brief First user block
    virtual uint16_t first_user_block() const = 0;
    //! @brief Last user block
    virtual uint16_t last_user_block() const = 0;
    //! @brief User area size (bytes)
    virtual uint16_t user_area_size() const = 0;
    //! @brief Unit size for read
    virtual uint16_t unit_size_read() const = 0;
    //! @brief Unit size for write
    virtual uint16_t unit_size_write() const = 0;

    //! @brief Maximum read blocks for NFC-F
    virtual uint8_t maximum_read_blocks() const
    {
        return 0;
    }
    //! @brief Maximum write blocks for NFC-F
    virtual uint8_t maximum_write_blocks() const
    {
        return 0;
    }
};

}  // namespace nfc
}  // namespace m5
#endif
