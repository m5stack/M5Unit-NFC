/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for NFC helper functions
*/
#include <gtest/gtest.h>
#include <M5Unified.h>
#include "nfc/nfc.hpp"

using namespace m5::nfc;

TEST(NFC, FileSystemHelpers)
{
    file_system_feature_t fs = 0;
    EXPECT_FALSE(is_file_system_memory(fs));
    EXPECT_FALSE(is_file_system_file(fs));
    EXPECT_FALSE(is_file_system_ISO(fs));
    EXPECT_FALSE(is_file_system_desfire(fs));
    EXPECT_FALSE(is_file_system_desfire_normal(fs));
    EXPECT_FALSE(is_file_system_desfire_light(fs));

    fs = FILE_SYSTEM_FLAT_MEMORY;
    EXPECT_TRUE(is_file_system_memory(fs));
    EXPECT_FALSE(is_file_system_file(fs));

    fs = FILE_SYSTEM_ISO7816_4;
    EXPECT_TRUE(is_file_system_file(fs));
    EXPECT_TRUE(is_file_system_ISO(fs));
    EXPECT_FALSE(is_file_system_desfire(fs));

    fs = FILE_SYSTEM_DESFIRE;
    EXPECT_TRUE(is_file_system_file(fs));
    EXPECT_TRUE(is_file_system_desfire(fs));
    EXPECT_TRUE(is_file_system_desfire_normal(fs));
    EXPECT_FALSE(is_file_system_desfire_light(fs));

    fs = FILE_SYSTEM_DESFIRE_LIGHT;
    EXPECT_TRUE(is_file_system_file(fs));
    EXPECT_TRUE(is_file_system_desfire(fs));
    EXPECT_FALSE(is_file_system_desfire_normal(fs));
    EXPECT_TRUE(is_file_system_desfire_light(fs));
}
