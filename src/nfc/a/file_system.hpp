/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file file_system.hpp
  @brief File system for MIFARE Plus, DESFire / ST25TA
*/
#ifndef M5_UNIT_UNIFIED_NFC_NFC_A_FILE_SYSTEM_HPP
#define M5_UNIT_UNIFIED_NFC_NFC_A_FILE_SYSTEM_HPP
#include <cstdint>
#include <vector>

namespace m5 {
namespace nfc {
namespace a {

struct FileInfo {
    uint8_t fileId;      // DESFire: FileNo, ST25TA: FileID (上位1byte省略でもOK)
    uint32_t size;       // バイト数
    uint8_t type;        // DESFire: file type enum, ST25TA: NDEF/CC/System enum
    uint8_t readAccess;  // アクセス条件など（DESFire用）
    uint8_t writeAccess;
};

class FileSystem {
public:
    enum class Category : uint8_t {
        Unknown,
        DESFire,
        St25TA,
    };

    explicit FileSystem(const Category c) : _category{c}
    {
    }
    virtual ~FileSystem() = default;

    inline Category category() const
    {
        return _category;
    }

    // ルート/アプリケーションの列挙
    virtual bool listApplications(std::vector<uint32_t>& aids) = 0;  // ST25TAは空 or 固定
    virtual bool selectApplication(const uint32_t aid)         = 0;  // ST25TAではダミー or 常にtrue

    // ファイル一覧
    virtual bool listFiles(std::vector<FileInfo>& files)                                                          = 0;
    virtual bool readFile(std::vector<uint8_t> rbuf, const uint8_t fileId, const uint32_t offset,
                          const uint32_t rlen)                                                                    = 0;
    virtual bool writeFile(const uint8_t fileId, const uint32_t offset, const uint8_t* wbuf, const uint32_t wlen) = 0;

private:
    Category _category{};
};

}  // namespace a
}  // namespace nfc
}  // namespace m5
#endif
