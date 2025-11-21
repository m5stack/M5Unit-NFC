/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a.hpp
  @brief Common layer for NFC-A related units

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: ISO14443-3 state names

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_A_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_A_HPP

#include "nfc/a/nfca.hpp"
#include "ndef_layer.hpp"
#include <memory>
#include <vector>

namespace m5 {

namespace unit {
class UnitMFRC522;  // M5Unit-RFID
class UnitWS1850S;  // M5Unit-RFID
class UnitST25R3916;
class CapST25R3916;

namespace nfc {

/*!
  @class NFCLayerA
  @brief Common interface layer for each chip of the NFC-A reader
 */
class NFCLayerA : public m5::nfc::NFCLayerInterface {
public:
    struct Adapter;
    explicit NFCLayerA(UnitMFRC522& u);  //  The implementation of this function is located in M5Unit-RFID
    explicit NFCLayerA(UnitWS1850S& u);  // The implementation of this function is located in M5Unit-RFID
    explicit NFCLayerA(UnitST25R3916& u);
    explicit NFCLayerA(CapST25R3916& u);

    /*!
      @brief Is the specified PICC (UID) currently active?
      @param uid UID to check
      @return True if this PICC is the one currently selected (ACTIVE state)
    */
    inline bool isActive(const m5::nfc::a::UID& uid) const
    {
        return _activeUID.valid() && _activeUID == uid;
    }
    /*!
      @brief Retrieve the currently activated PICC UID
      @return Active PICC UID
      @note Returns an empty UID if no PICC is selected (no ACTIVE state)
    */
    const m5::nfc::a::UID& activatedPICC() const
    {
        return _activeUID;
    }

    ///@name Detection and activation
    ///@{
    /*!
      @brief Send REQA to discover a PICC in IDLE
      @param[out] atqa ATQA received from PICC
      @return True if successful
      @post PICC transitions: IDLE -> READY on successful response
     */
    bool request(uint16_t& atqa);
    /*!
      @brief Send WUPA to wake a PICC from IDLE or HALT
      @param[out] atqa ATQA received from PICC
      @return True if successful
      @post PICC transitions: IDLE/HALT -> READY on successful response
     */
    bool wakeup(uint16_t& atqa);
    /*!
      @brief Detect idle devices
      @param[out] devices Detected PICC UIDs (one per activated PICC candidate)
      @param timeout_ms  Polling time budget in milliseconds
      @return True if successful
      @note The selected PICC is typically put into HALT during enumeration to allow discovering others
     */
    bool detect(std::vector<m5::nfc::a::UID>& devices, const uint32_t timeout_ms = 10 * 1000U);
    /*!
      @brief Select a PICC (anti-collision + SELECT cascade to ACTIVE)
      @param[out] uid The fully activated UID (single- or multi-cascade)
      @return True if successful
      @pre A PICC is in the READY state (after REQA/WUPA)
      @post PICC transitions: READY -> ACTIVE on successful response
     */
    bool select(m5::nfc::a::UID& uid);
    /*!
      @brief Activate a specific PICC by UID (anti-collision against the given UID)
      @param uid UID
      @return True if successful
      @pre PICC is READY state
      @post PICC transitions: READY -> ACTIVE on successful response
     */
    bool activate(const m5::nfc::a::UID& uid);
    /*!
      @brief Wake and activate a specific PICC by UID
      @param uid Target UID
      @return True if successful
      @post PICC transitions: IDLE/HALT -> READY -> ACTIVE on a successful sequence
     */
    bool reactivate(const m5::nfc::a::UID& uid);
    /*!
      @brief Reactivate the previously selected PICC
      @details This function attempts to recover communication with the currently stored
      _activeUID when the PICC has entered the HALT state, for example
      due to a protocol error, timeout, or loss of RF field synchronization.
      Internally performs a WUPA (Wake-Up) followed by anti-collision and SELECT
      sequence using the last known UID
      @return True if successful
      @pre A valid`_activeUID is stored (i.e., at least one PICC was previously activated)
      @note Use this to recover from transient communication errors without performing a full REQA/detect cycle
     */
    inline bool reactivate()
    {
        return reactivate(_activeUID);
    }

    ///@}

    ///@name For activated PICC
    ///@{
    /*!
      @brief Send HLTA to the currently selected PICC (deactivate)
      @return True if successful
      @pre A PICC is in the ACTIVE state
      @post PICC transitions: ACTIVE -> HALT on a successful response
     */
    bool deactivate();

    /*!
      @brief Read the 1 page
      @param rx Buffer (at least 4 bytes)
      @param addr Block/Page address
      @return True if successful
      @warning Only PICC supporting the FAST_READ command is possible
     */
    bool read4(uint8_t rx[4], const uint8_t addr);
    /*!
      @brief Read the 1 block / 4 page (16 bytes)
      @param rx Buffer (at least 16 bytes)
      @param addr Block/Page address
      @return True if successful
      @pre The block must be authenticated if MIFARE classic
     */
    bool read16(uint8_t rx[16], const uint8_t addr);
    /*!
      @brief Read any bytes from user area
      @details Continue reading only the user area from the first block of the user area until rx_len is satisfied
      @param rx Buffer
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param saddr Reading start block/page address
      @return True if successful
      @warning For FAST_READ-compatible devices, the rx is in 4-byte units. for others, it is in 16-byte units
      @pre Target blocks must be authenticatable using the specified key if MIFARE classic
    */
    bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr,
              const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);

    /*!
      @brief Write the 1 page (4 bytes)
      @param addr Block/Page address
      @param tx Buffer
      @param tx_len Buffer size
      @param safety Fail to write to out of the user memory area if true (safety measure)
      @return True if successful
      @warning Supports NTAG and UltraLight only
      @warning If the tx_len is less than 4 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 4 bytes, only the first 4 bytes will be written
     */
    bool write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety = true);
    /*!
      @brief Write the 1 block / 4 page (16 bytes)
      @param addr Block/Page address
      @param tx Buffef
      @param tx_len Buffer size
      @param safety Fail to write to out of the user memory area if true (safety measure)
      @return True if successful
      @warning If the tx_len is less than 16 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 16 bytes, only the first 16 bytes will be written
      @pre The block must be authenticated if MIFARE classic
    */
    bool write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety = true);
    /*!
      @brief Write any bytes to user area
      @details Continue writing only the user area from the first block of the user area until tx_len is satisfied
      @param saddr Writing start block/page address
      @param tx Buffer
      @param tx_len buffer size
      @return True if successful
      @warning For NTAG and UltraLight, the tx is in 4-byte units; for others, it is in 16-byte units
      @warning If the value is less than the unit, it is padded with 0x00
      @pre Target blocks must be authenticatable using the specified key if MIFARE classic
    */
    bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len,
               const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    ///@}

    ///@name For MIFARE classic
    ///@{
    /*!
      @brief Authentication by KeyA for MIFARE classsic
      @param block Authentication block
      @param key MIFARE classic key
      @param encrypted Is it already in an encrypted state?
      @return True if successful
    */
    bool mifareClassicAuthenticateA(
        const uint8_t block, const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Authentication by KeyB for MIFARE classic
      @param block Authentication block
      @param key MIFARE classic key
      @param encrypted Is it already in an encrypted state?
      @return True if successful
    */
    bool mifareClassicAuthenticateB(
        const uint8_t block, const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);

    /*!
      @brief Read the specific block access conditons
      @param[out] c123 Access bits Bit2:C1 Bit1:C2 Bit0:C3
      @param block Block
      @return True if successful
      @details Access conditions for the sector trailer
      |C1|C2|C3|KeyA read|KeyA write|Access bits read|Access bits write|KeyB raed|KeyB write|
      |---|---|---|---|---|---|---|---|---|
      |0|0|0|never|keyA |keyA  |never|keyA |keyA |
      |0|1|0|never|never|keyA  |never|keyA |never|
      |1|0|0|never|keyB |keyA/B|never|never|keyB |
      |1|1|0|never|never|keyA/B|never|never|never|
      |0|0|1|never|keyA |keyA  |keyA |keyA |keyA |
      |0|1|1|never|keyB |keyA/B|keyB |never|keyB |
      |1|0|1|never|never|keyA/B|keyB |never|never|
      |1|1|1|never|never|keyA/B|never|never|never|
      Access conditions for data blocks
      |C1|C2|C3|read|write|increment|decrement,transfer, restore|Application|
      |---|---|---|---|---|---|---|---|
      |0|0|0|keyA/B|keyA/B|keyA/B|keyA/B|transport configuration|
      |0|1|0|keyA/B|never |neve  |never |read/write block|
      |1|0|0|keyA/B|keyB  |never |never |read/write block|
      |1|1|0|keyA/B|keyB  |keyB  |keyA/B|value block|
      |0|0|1|keyA/B|never |never |keyA/B|value block|
      |0|1|1|keyB  |keyB  |never |never |read/write block|
      |1|0|1|keyB  |never |never |never |read/write block|
      |1|1|1|never |never |never |never |read/write block|
      @pre The authentication of the sector trailer to which the block belongs is in place
     */
    bool mifareClassicReadAccessCondition(uint8_t& c123, const uint8_t block);
    /*!
      @brief Write the specific block access conditons
      @param block Block
      @param c123 Access bits Bit2:C1 Bit1:C2 Bit0:C3
      @param akey KeyA
      @param bkey KeyB
      @return True if successful
      @sa About access condition mifareClassicReadAccessCondition
      @warning Since writes are performed in 16-byte units, key information must also be entered correctly
      @pre The authentication of the sector trailer to which the block belongs is in place
     */
    bool mifareClassicWriteAccessCondition(const uint8_t block, const uint8_t c123,
                                           const m5::nfc::a::mifare::classic::Key& akey,
                                           const m5::nfc::a::mifare::classic::Key& bkey);

    /*!
      @brief Is specific block the value block?
      @param[out] is_value_block true if block is the value block
      @param block Block
      @param key MIFARE classic key
      @return True if successful
      @pre The specified block is authenticated
     */
    bool mifareClassicIsValueBlock(bool& is_value_block, const uint8_t block);
    /*!
      @brief Read the specific block as the value block
      @param[out] value Value
      @param block Block
      @return True if successful
      @pre The specified block is authenticated
     */
    bool mifareClassicReadValueBlock(int32_t& value, const uint8_t block);
    /*!
      @brief Write the specific block as the value block
      @param block Block
      @param value Value
      @return True if successful
      @pre The specified block is authenticated
     */
    bool mifareClassicWriteValueBlock(const uint8_t block, const int32_t value);
    /*!
      @brief Decrement value of the value block
      @param block Block
      @param delta Delta
      @param transfer Transfer immediately if true
      @return True if successful
      @warning When transfer == false, the result is stored only in the internal buffer and is not written to the PICC
      @warning Use mifareClassicTransferValueBlock for writing from the internal buffer to PICC
      @pre The specified block is authenticated
      @pre The specified block must be a value block
     */
    bool mifareClassicDecrementValueBlock(const uint8_t block, const uint32_t delta, const bool transfer = true);
    /*!
      @brief Increment value of the value block
      @param block Block
      @param delta Delta
      @param transfer Transfer immediately if true
      @return True if successful
      @warning When transfer == false, the result is stored only in the internal buffer and is not written to the PICC
      @warning Use mifareClassicTransferValueBlock for writing from the internal buffer to PICC
      @pre The specified block is authenticated
      @pre The specified block must be a rechargeable value block
     */
    bool mifareClassicIncrementValueBlock(const uint8_t block, const uint32_t delta, const bool transfer = true);
    /*!
      @brief Transfer inner buffer value to block
      @param block Block
      @return True if successful
      @pre The specified block is authenticated
      @pre The specified block must be a value block
     */
    bool mifareClassicTransferValueBlock(const uint8_t block);
    /*!
      @brief Restore block value to inner buffer
      @param block Block
      @return True if successful
      @pre The specified block is authenticated
      @pre The specified block must be a value block
     */
    bool mifareClassicRestoreValueBlock(const uint8_t block);

    /*!
      @brief Write change to NFC Type-2 (NDEF) format
      @return True if successful
      @note Returns true if the data is already in NDEF format or if the PICC is an NTAG
      @warning Only MIFARE Ultralight,UltralightC
      @warning Changes are irreversible and cannot be undone
    */
    bool mifareUltralightChangeFormatToNTAG();
    ///@}

    ///@name For NDEF
    ///@{
    /*!
      @brief Is the PICC data in NDEF format?
      @paran[out] valid True if NDEF format
      @return True if successful
     */
    bool ndefIsValidFormat(bool& valid);
    /*!
      @brief Get the size of the NDEF message If the data is NDEF
      @param[out] size Size of th NDEF message, 0 means Empty or NOT NDEF
      @return True if successful
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefReadMessageSize(uint32_t& size);
    /*!
      @brief Read NDEF Messages
      @param[out] msgs Messgae vector
      @return True if successful
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefRead(std::vector<m5::nfc::ndef::Message>& msgs);
    /*!
      @brief Writed NDEF Messages
      @param msgs Messgae vector
      @return True if successful
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const std::vector<m5::nfc::ndef::Message>& msgs);
    /*!
      @brief Writed NDEF Message
      @param msg Messgae
      @return True if successful
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const m5::nfc::ndef::Message& msg);
    ///@}

    /*!
      @brief Dump all blocks for debug
      @param key MIFARE classic key
      @pre All blocks must be authenticatable using the specified key if MIFARE classic
     */
    bool dump(const m5::nfc::a::mifare::classic::Key& mkey = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Dump 1 block
      @param addr Block address
      @note The sector to which the block belongs is dumped
      @pre The block must be authenticated if MIFARE classic
    */
    bool dump(const uint8_t block);
    ///@}

protected:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr) override;
    virtual bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len) override;
    virtual uint16_t firstUserBlock() override;
    virtual uint16_t lastUserBlock() override;

    bool read_using_fast(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr);
    bool read_using_read16(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr,
                           const m5::nfc::a::mifare::classic::Key& key);
    bool write_using_write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len);
    bool write_using_write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                             const m5::nfc::a::mifare::classic::Key& key);

    bool mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block, const uint32_t arg = 0);

    bool ntag_check_format();

    bool dump_sector_structure(const m5::nfc::a::UID& uid, const m5::nfc::a::mifare::classic::Key& key);
    bool dump_sector(const uint8_t sector);
    bool dump_page_structure(const uint16_t maxPage);
    bool dump_page(const uint8_t page, const uint16_t maxPage);

    static bool push_back_uid(std::vector<m5::nfc::a::UID>& v, const m5::nfc::a::UID& uid);

protected:
    m5::nfc::a::UID _activeUID{};

private:
    std::unique_ptr<Adapter> _impl;
    m5::nfc::ndef::NDEFLayer _ndef;
};

// Impl for units
struct NFCLayerA::Adapter {
    virtual ~Adapter() = default;

    virtual uint16_t max_fifo_depth() = 0;

    virtual bool request(uint16_t& atqa) = 0;
    virtual bool wakeup(uint16_t& atqa)  = 0;

    virtual bool select(m5::nfc::a::UID& uid)         = 0;
    virtual bool activate(const m5::nfc::a::UID& uid) = 0;
    virtual bool deactivate()                         = 0;

    virtual bool nfca_read_block(uint8_t rx[16], const uint8_t addr)        = 0;  // READ
    virtual bool nfca_write_block(const uint8_t addr, const uint8_t tx[16]) = 0;  // WRITE_BLOCK
    virtual bool nfca_write_page(const uint8_t addr, const uint8_t tx[4])   = 0;  // WRITE_PAGE

    virtual bool mifare_classic_authenticate(const bool auth_a, const m5::nfc::a::UID& uid, const uint8_t block,
                                             const m5::nfc::a::mifare::classic::Key& key) = 0;
    virtual bool mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block,
                                            const uint32_t arg = 0)                       = 0;

    virtual bool ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage,
                                const uint8_t epage) = 0;  // FAST_READ

    //    virtual bool mifare_classic_read_block(uint8_t* rx, uint16_t& rx_len, const uint16_t addr)             = 0;
    //    virtual bool mifare_classic_write_block(const uint16_t addr, const uint8_t* tx, const uint16_t tx_len) = 0;

protected:
};

}  // namespace nfc
}  // namespace unit
}  // namespace m5

#endif
