/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for MIFARE
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/a/mifare.hpp"
#include <cstring>

using namespace m5::nfc::a::mifare;

TEST(MIFARE_Classic, SectorTrailer)
{
    using namespace classic;

    // is_sector_trailer_block (small sectors: blocks 0-127, 4 blocks each)
    EXPECT_FALSE(is_sector_trailer_block(0));
    EXPECT_FALSE(is_sector_trailer_block(1));
    EXPECT_FALSE(is_sector_trailer_block(2));
    EXPECT_TRUE(is_sector_trailer_block(3));
    EXPECT_FALSE(is_sector_trailer_block(4));
    EXPECT_TRUE(is_sector_trailer_block(7));
    EXPECT_TRUE(is_sector_trailer_block(63));

    // Large sectors: blocks 128+, 16 blocks each
    EXPECT_FALSE(is_sector_trailer_block(128));
    EXPECT_TRUE(is_sector_trailer_block(143));
    EXPECT_FALSE(is_sector_trailer_block(144));
    EXPECT_TRUE(is_sector_trailer_block(159));

    // get_sector_trailer_block
    EXPECT_EQ(get_sector_trailer_block(0), 3);
    EXPECT_EQ(get_sector_trailer_block(1), 3);
    EXPECT_EQ(get_sector_trailer_block(2), 3);
    EXPECT_EQ(get_sector_trailer_block(3), 3);
    EXPECT_EQ(get_sector_trailer_block(4), 7);
    EXPECT_EQ(get_sector_trailer_block(60), 63);
    EXPECT_EQ(get_sector_trailer_block(128), 143);
    EXPECT_EQ(get_sector_trailer_block(144), 159);

    // get_sector
    EXPECT_EQ(get_sector(0), 0);
    EXPECT_EQ(get_sector(3), 0);
    EXPECT_EQ(get_sector(4), 1);
    EXPECT_EQ(get_sector(7), 1);
    EXPECT_EQ(get_sector(60), 15);
    EXPECT_EQ(get_sector(63), 15);
    EXPECT_EQ(get_sector(124), 31);
    EXPECT_EQ(get_sector(127), 31);
    EXPECT_EQ(get_sector(128), 32);
    EXPECT_EQ(get_sector(143), 32);
    EXPECT_EQ(get_sector(144), 33);

    // get_permission_offset
    EXPECT_EQ(get_permission_offset(0), 0);
    EXPECT_EQ(get_permission_offset(1), 1);
    EXPECT_EQ(get_permission_offset(2), 2);
    EXPECT_EQ(get_permission_offset(3), 3);
    EXPECT_EQ(get_permission_offset(4), 0);

    // get_sector_trailer_block_from_sector
    EXPECT_EQ(get_sector_trailer_block_from_sector(0), 3);
    EXPECT_EQ(get_sector_trailer_block_from_sector(1), 7);
    EXPECT_EQ(get_sector_trailer_block_from_sector(15), 63);
    EXPECT_EQ(get_sector_trailer_block_from_sector(31), 127);
    EXPECT_EQ(get_sector_trailer_block_from_sector(32), 143);
    EXPECT_EQ(get_sector_trailer_block_from_sector(33), 159);
}

TEST(MIFARE_Classic, ValueBlockPermission)
{
    using namespace classic;

    EXPECT_TRUE(can_value_block_permission(0x00));   // Transport
    EXPECT_TRUE(can_value_block_permission(0x01));   // Debit only
    EXPECT_TRUE(can_value_block_permission(0x06));   // Full operation
    EXPECT_FALSE(can_value_block_permission(0x02));  // Other
    EXPECT_FALSE(can_value_block_permission(0x03));
    EXPECT_FALSE(can_value_block_permission(0x04));
    EXPECT_FALSE(can_value_block_permission(0x05));
    EXPECT_FALSE(can_value_block_permission(0x07));
}

TEST(MIFARE_Classic, ValueBlock)
{
    using namespace classic;

    // Encode value block
    uint8_t buf[16]{};
    int32_t test_value = 12345;
    uint8_t test_addr  = 5;

    const uint8_t* encoded = encode_value_block(buf, test_value, test_addr);
    EXPECT_NE(encoded, nullptr);

    // Decode value block
    int32_t decoded_value = 0;
    uint8_t decoded_addr  = 0;
    EXPECT_TRUE(decode_value_block(decoded_value, decoded_addr, buf));
    EXPECT_EQ(decoded_value, test_value);
    EXPECT_EQ(decoded_addr, test_addr);

    // Test negative value
    test_value = -9999;
    encode_value_block(buf, test_value, test_addr);
    EXPECT_TRUE(decode_value_block(decoded_value, decoded_addr, buf));
    EXPECT_EQ(decoded_value, test_value);

    // Test zero
    test_value = 0;
    encode_value_block(buf, test_value, test_addr);
    EXPECT_TRUE(decode_value_block(decoded_value, decoded_addr, buf));
    EXPECT_EQ(decoded_value, 0);

    // Test max/min values
    test_value = INT32_MAX;
    encode_value_block(buf, test_value, test_addr);
    EXPECT_TRUE(decode_value_block(decoded_value, decoded_addr, buf));
    EXPECT_EQ(decoded_value, INT32_MAX);

    test_value = INT32_MIN;
    encode_value_block(buf, test_value, test_addr);
    EXPECT_TRUE(decode_value_block(decoded_value, decoded_addr, buf));
    EXPECT_EQ(decoded_value, INT32_MIN);

    // Invalid value block (corrupt data)
    std::memset(buf, 0xFF, sizeof(buf));
    EXPECT_FALSE(decode_value_block(decoded_value, decoded_addr, buf));

    // Corrupt complement bytes
    encode_value_block(buf, 123, 0x12);
    buf[4] ^= 0x01;
    EXPECT_FALSE(decode_value_block(decoded_value, decoded_addr, buf));

    // Corrupt address complement
    encode_value_block(buf, 456, 0x34);
    buf[13] ^= 0x01;
    EXPECT_FALSE(decode_value_block(decoded_value, decoded_addr, buf));

    // Corrupt mirror bytes
    encode_value_block(buf, 789, 0x56);
    buf[8] ^= 0x01;
    EXPECT_FALSE(decode_value_block(decoded_value, decoded_addr, buf));
}

TEST(MIFARE_Classic, AccessBits)
{
    using namespace classic;

    // Default transport configuration (all 0x00)
    uint8_t abits[3]{};
    uint8_t permissions[4] = {0x00, 0x00, 0x00, 0x00};

    EXPECT_TRUE(encode_access_bits(abits, permissions));

    // Decode back
    uint8_t decoded_perms[4]{};
    EXPECT_TRUE(decode_access_bits(decoded_perms, abits));
    EXPECT_EQ(decoded_perms[0], permissions[0]);
    EXPECT_EQ(decoded_perms[1], permissions[1]);
    EXPECT_EQ(decoded_perms[2], permissions[2]);
    EXPECT_EQ(decoded_perms[3], permissions[3]);

    // Test with different permissions
    permissions[0] = 0x01;  // Value block debit only
    permissions[1] = 0x06;  // Value block full
    permissions[2] = 0x00;  // Read/write
    permissions[3] = 0x01;  // Sector trailer default

    EXPECT_TRUE(encode_access_bits(abits, permissions[0], permissions[1], permissions[2], permissions[3]));
    EXPECT_TRUE(decode_access_bits(decoded_perms, abits[0], abits[1], abits[2]));
    EXPECT_EQ(decoded_perms[0], permissions[0]);
    EXPECT_EQ(decoded_perms[1], permissions[1]);
    EXPECT_EQ(decoded_perms[2], permissions[2]);
    EXPECT_EQ(decoded_perms[3], permissions[3]);

    // Corrupt access bits
    abits[0] ^= 0x01;
    EXPECT_FALSE(decode_access_bits(decoded_perms, abits));

    // Invalid permission bits (upper bits set) should fail encode
    EXPECT_FALSE(encode_access_bits(abits, 0x08, 0x00, 0x00, 0x00));
}

TEST(MIFARE_Classic, Key)
{
    using namespace classic;

    // Default key
    EXPECT_EQ(DEFAULT_KEY.size(), 6u);
    for (auto b : DEFAULT_KEY) {
        EXPECT_EQ(b, 0xFF);
    }

    // Key type
    Key myKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    EXPECT_EQ(myKey.size(), 6u);
    EXPECT_EQ(myKey[0], 0x01);
    EXPECT_EQ(myKey[5], 0x06);
}

TEST(MIFARE_DESFire, AccessRights)
{
    using namespace desfire;

    // Read access rights
    // Format: [Read][Write][R/W][Change] (4 bits each)

    // Free access (0xE in read position)
    EXPECT_EQ(required_read_key_no_from_access_rights(0xE000), access_free);

    // Key 0 required
    EXPECT_EQ(required_read_key_no_from_access_rights(0x0000), 0);

    // Key 3 required
    EXPECT_EQ(required_read_key_no_from_access_rights(0x3000), 3);

    // Read denied but R/W free
    EXPECT_EQ(required_read_key_no_from_access_rights(0xF0E0), access_free);

    // Read denied, R/W key 2
    EXPECT_EQ(required_read_key_no_from_access_rights(0xF020), 2);

    // Both denied
    EXPECT_EQ(required_read_key_no_from_access_rights(0xF0F0), access_denied);

    // Write access rights
    // Free access
    EXPECT_EQ(required_write_key_no_from_access_rights(0x0E00), access_free);

    // Key 1 required
    EXPECT_EQ(required_write_key_no_from_access_rights(0x0100), 1);

    // Write denied (0xF) but R/W free (0xE)
    EXPECT_EQ(required_write_key_no_from_access_rights(0x0FE0), access_free);

    // Write denied, R/W key 4
    EXPECT_EQ(required_write_key_no_from_access_rights(0x0F40), 4);

    // Both denied
    EXPECT_EQ(required_write_key_no_from_access_rights(0x0FF0), access_denied);
}

TEST(MIFARE_DESFire, Constants)
{
    using namespace desfire;

    EXPECT_EQ(DESFIRE_NDEF_APP_ID, 0x000001u);
    EXPECT_EQ(DESFIRE_CC_FILE_NO, 0x01);
    EXPECT_EQ(DESFIRE_NDEF_FILE_NO, 0x02);
    EXPECT_EQ(sizeof(DESFIRE_NDEF_AID), 3u);

    // DESFire Light
    EXPECT_EQ(sizeof(DESFIRE_LIGHT_DF_NAME), 16u);
    EXPECT_EQ(DESFIRE_LIGHT_DF_FID, 0xDF01);
    EXPECT_EQ(DESFIRE_LIGHT_CC_FILE_NO, 0x00);
    EXPECT_EQ(DESFIRE_LIGHT_NDEF_FILE_NO, 0x04);

    // Default key (all zeros)
    for (auto b : DESFIRE_DEFAULT_KEY) {
        EXPECT_EQ(b, 0x00);
    }
}

TEST(MIFARE_Plus, Key)
{
    using namespace plus;

    // Default AES key (all zeros)
    EXPECT_EQ(DEFAULT_KEY.size(), 16u);
    for (auto b : DEFAULT_KEY) {
        EXPECT_EQ(b, 0x00);
    }

    // Default FF key (all 0xFF)
    EXPECT_EQ(DEFAULT_FF_KEY.size(), 16u);
    for (auto b : DEFAULT_FF_KEY) {
        EXPECT_EQ(b, 0xFF);
    }

    // AESKey type
    AESKey myKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    EXPECT_EQ(myKey.size(), 16u);
}

TEST(MIFARE, HistoricalBytes)
{
    // Check historical bytes constants
    EXPECT_EQ(historical_bytes_mifare_plus_s.size(), 7u);
    EXPECT_EQ(historical_bytes_mifare_plus_x_ev.size(), 7u);
    EXPECT_EQ(historical_bytes_mifare_plus_se0.size(), 7u);
    EXPECT_EQ(historical_bytes_mifare_plus_se1.size(), 7u);
    EXPECT_EQ(historical_bytes_mifare_plus_se2.size(), 7u);

    // Verify they are different
    EXPECT_NE(historical_bytes_mifare_plus_s, historical_bytes_mifare_plus_x_ev);
    EXPECT_NE(historical_bytes_mifare_plus_se0, historical_bytes_mifare_plus_se1);
}
