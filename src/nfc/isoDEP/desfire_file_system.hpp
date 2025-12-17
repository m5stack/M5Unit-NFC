/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file desfire_file_system.hpp
  @brief File system base using isoDEP for MIFARE DESFire
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_ISODEP_DESFIRE_FILE_SYSTEM_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_ISODEP_DESFIRE_FILE_SYSTEM_HPP
#include "file_system.hpp"
#include <array>

namespace m5 {
namespace nfc {
class NFCLayerA;
namespace a {
namespace mifare {
/*!
  @namespace desfire
  @brief For MIFARE DESFire
 */
namespace desfire {

struct desfire_aid_t {
    uint8_t aid[3]{};  // BE
    uint8_t _pad{};
    inline constexpr uint32_t aid24() const noexcept
    {
        // Big-endian
        return ((uint32_t)aid[0] << 16) | ((uint32_t)aid[1] << 8) | aid[2];
    }
    inline constexpr const uint8_t* data() const noexcept
    {
        return aid;
    }
    inline explicit operator uint32_t() const noexcept
    {
        return aid24();
    }
};

inline bool operator==(const desfire_aid_t& a, const desfire_aid_t& b) noexcept
{
    return a.aid[0] == b.aid[0] && a.aid[1] == b.aid[1] && a.aid[2] == b.aid[2];
}

inline bool operator!=(const desfire_aid_t& a, const desfire_aid_t& b) noexcept
{
    return !(a == b);
}

inline bool operator<(const desfire_aid_t& a, const desfire_aid_t& b) noexcept
{
    return a.aid24() < b.aid24();
}

/*!
  @brief Make native wrap command
  @details Something similar to ADPU but different
  @param ins Native INS
  @param data Data
  @param data_len Data length
  @return Constructed command data
 */
std::vector<uint8_t> make_native_wrap_command(const uint8_t ins, const uint8_t* data = nullptr,
                                              const uint16_t data_len = 0);

//! @brief Is the received data still waiting for a response?
inline bool is_more(const uint8_t* rx, const uint16_t rx_len)
{
    return rx && rx_len >= 2 && rx[rx_len - 2] == 0x91 && rx[rx_len - 1] == 0xAF;
}
//! @brief Is the status of the received data successful?
inline bool is_successful(const uint8_t* rx, const uint16_t rx_len)
{
    return rx && rx_len >= 2 && rx[rx_len - 2] == 0x91 && rx[rx_len - 1] == 0x00;
}

/*!
  @class DESFireFileSystem
  @brief File system for MIFARE DESFire
 */
class DESFireFileSystem : public FileSystem {
public:
    explicit DESFireFileSystem(m5::nfc::NFCLayerA& layer);

    inline bool selectApplication(const desfire_aid_t& aid, const uint32_t timeout_ms = 200)
    {
        return selectApplication(aid.data(), timeout_ms);
    }
    bool selectApplication(const uint8_t aid[3], const uint32_t timeout_ms = 200);
    bool selectApplication(const uint32_t aid24 = 0u, const uint32_t timeout_ms = 200);

    bool getApplicationIDs(std::vector<desfire_aid_t>& out, const uint32_t timeout_ms = 200);

    bool getFileIDs(std::vector<uint8_t>& out, const uint32_t timeout_ms = 200);

    bool readData(uint8_t fileNo, std::vector<uint8_t>& out, uint32_t timeout_ms = 400);
    bool readData(uint8_t fileNo, uint32_t offset, uint32_t length, std::vector<uint8_t>& out,
                  const uint32_t timeout_ms = 400);

protected:
    bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len);
};

}  // namespace desfire
}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
#endif
