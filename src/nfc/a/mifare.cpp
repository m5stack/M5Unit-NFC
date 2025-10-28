/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file mifare.cpp
  @brief Mifare definitions
*/
#include "mifare.hpp"
#include <M5Utility.hpp>

namespace m5 {
namespace nfc {
namespace a {
namespace mifare {

const Key DEFAULT_CLASSIC_KEY = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

namespace classic {
bool decode_value_block(int32_t& value, uint8_t& addr, const uint8_t* buf)
{
    if (*((uint32_t*)&buf[0]) == *((uint32_t*)&buf[8]) && *((uint32_t*)&buf[0]) == ~*((uint32_t*)&buf[4]) &&
        *((uint16_t*)&buf[12]) == *((uint16_t*)&buf[14]) && buf[12] == (uint8_t)~buf[13]) {
        value = ((int32_t)buf[3]) << 24 | ((int32_t)buf[2]) << 16 | ((int32_t)buf[1]) << 8 | buf[0];
        addr  = buf[12];
        return true;
    }
    return false;
}

const uint8_t* encode_value_block(uint8_t* buf, const int32_t value, const uint8_t addr)
{
    buf[0] = buf[8] = (value >> 0) & 0xFF;
    buf[1] = buf[9] = (value >> 8) & 0xFF;
    buf[2] = buf[10] = (value >> 16) & 0xFF;
    buf[3] = buf[11] = (value >> 24) & 0xFF;

    buf[4] = ~buf[0];
    buf[5] = ~buf[1];
    buf[6] = ~buf[2];
    buf[7] = ~buf[3];

    buf[12] = buf[14] = addr;
    buf[13] = buf[15] = ~addr;
    return buf;
}

bool encode_access_bits(uint8_t abits[3], const uint8_t p0, const uint8_t p1, const uint8_t p2, const uint8_t p3)
{
    // Valid up to the third bit in each value
    if ((p0 & 0xF8) | (p1 & 0xF8) | (p2 & 0xF8) | (p3 & 0xF8)) {
        return false;
    }
    uint8_t c1 = ((p3 & 4) << 1) | ((p2 & 4) << 0) | ((p1 & 4) >> 1) | ((p0 & 4) >> 2);
    uint8_t c2 = ((p3 & 2) << 2) | ((p2 & 2) << 1) | ((p1 & 2) << 0) | ((p0 & 2) >> 1);
    uint8_t c3 = ((p3 & 1) << 3) | ((p2 & 1) << 2) | ((p1 & 1) << 1) | ((p0 & 1) << 0);

    abits[0] = ((~c2 & 0x0F) << 4) | (~c1 & 0x0F);
    abits[1] = (c1 << 4) | (~c3 & 0x0F);
    abits[2] = (c3 << 4) | c2;
    return true;
}

bool decode_access_bits(uint8_t permissions[4], const uint8_t ab0, const uint8_t ab1, const uint8_t ab2)
{
    // value bits
    uint8_t c1 = (ab1 >> 4) & 0x0F;
    uint8_t c2 = ab2 & 0x0F;
    uint8_t c3 = (ab2 >> 4) & 0x0F;
    // negated bits
    uint8_t n1 = (~(ab0 & 0x0F)) & 0x0F;
    uint8_t n2 = (~((ab0 >> 4) & 0x0F)) & 0x0F;
    uint8_t n3 = (~(ab1 & 0x0F)) & 0x0F;

    bool valid = (c1 == n1) && (c2 == n2) && (c3 == n3);
    if (valid || true) {
        permissions[0] = ((c1 & 1) << 2) | ((c2 & 1) << 1) | ((c3 & 1) << 0);
        permissions[1] = ((c1 & 2) << 1) | ((c2 & 2) << 0) | ((c3 & 2) >> 1);
        permissions[2] = ((c1 & 4) << 0) | ((c2 & 4) >> 1) | ((c3 & 4) >> 2);
        permissions[3] = ((c1 & 8) >> 1) | ((c2 & 8) >> 2) | ((c3 & 8) >> 3);
    }
    return valid;
}

}  // namespace classic
}  // namespace mifare
}  // namespace a
}  // namespace nfc
}  // namespace m5
