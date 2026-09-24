/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
  @file nfc_layer_a.hpp
  @brief Common layer for NFC-A

  @note Glossary
  - PCD: Proximity Coupling Device (reader)
  - PICC: Proximity Integrated Circuit Card (card/tag, target device)
  - IDLE/READY/ACTIVE/HALT: ISO14443-3 state names

  @note In NFC Forum (NDEF) context, a PICC is often called a "Tag"
*/
#ifndef M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_A_HPP
#define M5_UNIT_NFC_NFC_LAYER_NFC_LAYER_A_HPP

#include "nfc/layer/nfc_layer.hpp"
#include "nfc/a/nfca.hpp"
#include "nfc/isoDEP/isoDEP.hpp"
#include "nfc/layer/ndef_layer.hpp"
#include "nfc/ndef/ndef.hpp"
#include <vector>
#include <memory>

namespace m5 {

namespace unit {
class UnitMFRC522;  // M5Unit-RFID
class UnitWS1850S;  // M5Unit-RFID
class UnitST25R3916;
class CapST25R3916;
}  // namespace unit

namespace nfc {

/*!
  @class NFCLayerA
  @brief Common interface layer for each chip of the NFC-A reader
 */
class NFCLayerA : public m5::nfc::NFCLayerInterface {
public:
    struct Adapter;
    //! @brief Constructor with UnitMFRC522 (M5Unit-RFID)
    explicit NFCLayerA(m5::unit::UnitMFRC522& u);  // The implementation of this function is located in M5Unit-RFID
    //! @brief Constructor with UnitWS1850S (M5Unit-RFID)
    explicit NFCLayerA(m5::unit::UnitWS1850S& u);  // The implementation of this function is located in M5Unit-RFID
    //! @brief Constructor with UnitST25R3916
    explicit NFCLayerA(m5::unit::UnitST25R3916& u);
    //! @brief Constructor with CapST25R3916 (SPI variant)
    explicit NFCLayerA(m5::unit::CapST25R3916& u);
    /*!
      @brief Constructor with a chip adapter
      @param adapter Adapter that drives the chip
      @note Lets a chip this library does not know about be used without editing this header. The
      layer takes ownership of the adapter
      @warning The adapter must not be null
     */
    explicit NFCLayerA(std::unique_ptr<Adapter> adapter);
    virtual ~NFCLayerA();

    ///@name override
    ///@{
    /*!
      @brief Transceive (NFC-A)
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if successful
     */
    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) override;
    // virtual bool transmit(const uint8_t* tx, const uint16_t tx_len, const uint32_t timeout_ms) override;
    // virtual bool receive(uint8_t* rx, uint16_t& rx_len, const uint32_t timeout_ms) override;
    /*!
      @brief Supported NFC Forum tag type
      @return NFC Forum tag type supported by the active PICC
     */
    virtual m5::nfc::NFCForumTag supportsNFCTag() const override;
    /*!
      @brief Supported file system features
      @return File system feature bits supported by the active PICC
     */
    virtual file_system_feature_t supportsFilesystem() const override;
    /*!
      @brief Get ISO-DEP context
      @return Pointer to ISO-DEP context
     */
    virtual m5::nfc::isodep::IsoDEP* isoDEP() override
    {
        return &_isoDEP;
    }
    /*!
      @brief Maximum FIFO depth in bytes
      @return Maximum FIFO depth in bytes
     */
    virtual uint16_t maximum_fifo_depth() const override;
    ///@}

    /*!
      @brief Is the specified PICC currently active?
      @param picc PICC to check
      @return True if this PICC is the one currently selected (ACTIVE state)
    */
    inline bool isActive(const m5::nfc::a::PICC& picc) const
    {
        return _activePICC.valid() && _activePICC == picc;
    }
    /*!
      @brief Retrieve the currently activated PICC
      @return Active PICC
      @note Returns an empty PICC if no PICC is selected (no ACTIVE state)
    */
    const m5::nfc::a::PICC& activatedPICC() const
    {
        return _activePICC;
    }
    /*!
      @brief Get the NFC-A activation configuration
      @return Current configuration (RATS FSDI/CID)
    */
    inline m5::nfc::a::config_t config() const
    {
        return _cfg;
    }
    /*!
      @brief Set the NFC-A activation configuration
      @param cfg Configuration. fsdi is clamped to [0,8], cid to [0,14]
      @note Affects the RATS sent during the next select()/activate()/reactivate()
    */
    void config(const m5::nfc::a::config_t& cfg);

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
      @brief Detect single idle PICC
      @param[out] picc Detected PICC
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note The detected PICC is typically put into HALT during enumeration to allow discovering others
      @note To identify the type, call NFCLayerA::identify
      @warning The type of activated PICC is determined solely by SAK and is provisional
     */
    bool detect(m5::nfc::a::PICC& picc, const uint32_t timeout_ms = 100U);
    /*!
      @brief Detect idle PICCs
      @param[out] piccs Detected PICCs (one per activated PICC candidate)
      @param timeout_ms  Polling time budget in milliseconds
      @return True if detected
      @note The detected PICC is typically put into HALT during enumeration to allow discovering others
      @note To identify the type, call NFCLayerA::identify
      @warning The type of activated PICC is determined solely by SAK and is provisional
     */
    bool detect(std::vector<m5::nfc::a::PICC>& piccs, const uint32_t timeout_ms = 1000U);
    /*!
      @brief Select a PICC (anti-collision + SELECT cascade to ACTIVE)
      @param[out] picc The fully activated PICC (single- or multi-cascade)
      @return True if successful
      @warning The type of activated PICC is determined solely by SAK and is provisional
      @note To identify the type, call NFCLayerA::identify
      @pre A PICC is in the READY state (after REQA/WUPA)
      @post PICC transitions: READY -> ACTIVE on successful response
     */
    bool select(m5::nfc::a::PICC& picc);
    /*!
      @brief Activate a specific PICC  (anti-collision against the given PICC)
      @param picc PICC
      @param force_rats Force Request_rats (For Plus SL1/2)
      @return True if successful
      @pre PICC is READY state
      @post PICC transitions: READY -> ACTIVE on successful response
     */
    bool activate(const m5::nfc::a::PICC& picc, const bool force_rats = false);
    /*!
      @brief Wake and activate a specific PICC by PICC
      @param picc Target PICC
      @param force_rats Force Request_rats (For Plus SL1/2)
      @return True if successful
      @post PICC transitions: IDLE/HALT -> READY -> ACTIVE on a successful sequence
     */
    bool reactivate(const m5::nfc::a::PICC& picc, const bool force_rats = false);
    /*!
      @brief Reactivate the previously selected PICC
      @details This function attempts to recover communication with the currently stored
      _activePICC when the PICC has entered the HALT state, for example
      due to a protocol error, timeout, or loss of RF field synchronization.
      Internally performs a WUPA (Wake-Up) followed by anti-collision and SELECT
      sequence using the last known PICC
      @return True if successful
      @pre A valid`_activePICC is stored (i.e., at least one PICC was previously activated)
      @note Use this to recover from transient communication errors without performing a full REQA/detect cycle
     */
    inline bool reactivate()
    {
        return reactivate(_activePICC);
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
      @brief Identify the specified PICC type
      @details Classification Based on AN10883
      @param[in/out] picc PICC
      @return True if successful
      @warning Before calling, the previously active PICC is deactivated
      @post PICC transitions: ACTIVE -> HALT, whether the type was identified or not
      @note Telling the types apart means sending commands that only some of them answer, which
      leaves the PICC in a state that depends on what it is. The PICC is therefore halted before
      returning, so that it is always left the same way. Call NFCLayerA::reactivate to work with it
     */
    bool identify(m5::nfc::a::PICC& picc);

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
      @warning For FAST_READ-compatible PICC, the rx is in 4-byte units. for others, it is in 16-byte units
      @pre Target blocks must be authenticatable using the specified key if MIFARE classic
    */
    bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr,
              const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Read any bytes from user area (MIFARE Plus SL3)
      @param rx Buffer
      @param[in/out] rx_len in:buffer size, out:actual read size
      @param saddr Reading start block address
      @param key AES sector key (for MIFARE Plus SL3)
      @return True if successful
      @warning The rx is in 16-byte units
      @pre Target blocks must be authenticatable using the specified key
    */
    bool read(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr, const m5::nfc::a::mifare::plus::AESKey& key);

    /*!
      @brief Write the 1 page (4 bytes)
      @param addr Block/Page address
      @param tx Buffer
      @param tx_len Buffer size
      @param safety Fail to write to out of the user memory area if true (safety measure)
      @return True if successful
      @warning Supports NTAG and Ultralight series  only
      @warning If the tx_len is less than 4 bytes, the remaining space is filled with 0x00
      @warning If the tx_len is larger than 4 bytes, only the first 4 bytes will be written
     */
    bool write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len, const bool safety = true);
    /*!
      @brief Write the 1 block / 4 page (16 bytes)
      @param addr Block/Page address
      @param tx Buffer
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
      @warning For NTAG and Ultralight series, the tx is in 4-byte units; for others, it is in 16-byte units
      @warning If the value is less than the unit, it is padded with 0x00
      @pre Target blocks must be authenticatable using the specified key if MIFARE classic
    */
    bool write(const uint8_t saddr, const uint8_t* tx, const uint16_t tx_len,
               const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Write any bytes to user area (MIFARE Plus SL3)
      @param addr Writing start block address
      @param tx Buffer
      @param tx_len Buffer size
      @param key AES sector key (for MIFARE Plus SL3)
      @return True if successful
      @warning The tx is in 16-byte units
      @pre Target blocks must be authenticatable using the specified key
     */
    bool write(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
               const m5::nfc::a::mifare::plus::AESKey& key);

    /*!
      @brief Dump all blocks/files
      @param key MIFARE classic key for Classic
      @return True if successful
      @pre All blocks must be authenticatable using the specified key if MIFARE classic
     */
    bool dump(const m5::nfc::a::mifare::classic::Key& mkey = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Dump 1 block
      @param addr Block address
      @return True if successful
      @note The sector to which the block belongs is dumped
      @pre The block must be authenticated if MIFARE classic/PlusS3
    */
    bool dump(const uint8_t block);
    ///@}

    ///@note For activated PICC
    ///@name For MIFARE classic
    ///@{
    /*!
      @brief Authentication by KeyA for MIFARE classic
      @param block Authentication block
      @param key MIFARE classic key
      @return True if successful
    */
    bool mifareClassicAuthenticateA(
        const uint8_t block, const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Authentication by KeyB for MIFARE classic
      @param block Authentication block
      @param key MIFARE classic key
      @return True if successful
    */
    bool mifareClassicAuthenticateB(
        const uint8_t block, const m5::nfc::a::mifare::classic::Key& key = m5::nfc::a::mifare::classic::DEFAULT_KEY);

    /*!
      @brief Read the specific block access conditions
      @param[out] c123 Access bits Bit2:C1 Bit1:C2 Bit0:C3
      @param block Block
      @return True if successful
      @details Access conditions for the sector trailer
      |C1|C2|C3|KeyA read|KeyA write|Access bits read|Access bits write|KeyB read|KeyB write|
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
      @brief Write the specific block access conditions
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
    ///@}

    ///@note For activated PICC
    ///@name For MIFARE ultralight
    ///@{
    /*!
      @brief Write change to NFC Type-2 (NDEF) format for MIFARE Ultralight/C
      @return True if successful
      @note Returns true if the data is already in NDEF format or if the PICC is an NTAG
      @warning Only MIFARE Ultralight series
      @warning Changes are irreversible and cannot be undone
      @warning If the relevant area has already been overwritten, changes may not be possible
    */
    bool mifareUltralightChangeFormatToNDEF();
    ///@}

    ///@note For activated PICC
    ///@name For MIFARE ultralightC
    ///@{
    /*!
      @brief Authentication for MIFARE UltralightC
      @param key 16-byte authentication key
      @return True if successful
     */
    bool mifareUltralightCAuthenticate(const uint8_t key[16]);
    ///@}

    ///@note For activated PICC
    ///@name For MIFARE Plus
    ///@{
    /*!
      @brief Upgrade security level to SL1 (Classic compatibility mode)
      @param card_config_key Card Configuration Key (AES)
      @param card_master_key Card Master Key (AES)
      @param l2_switch_key Level 2 Switch Key (AES, for MIFARE Plus X/EV2 SL2 only)
      @param l3_switch_key Level 3 Switch Key (AES, for SL3)
      @param aes_sector_key AES sector key (for SL2/SL3, written to 0x4000+)
      @param key_a Crypto1 Key A (applies to all sectors)
      @param key_b Crypto1 Key B (applies to all sectors)
      @return True if successful
      @warning This operation is irreversible
      @warning Access bits will be reset to the transport configuration
     */
    bool mifarePlusUpgradeSecurityLevel1(
        const m5::nfc::a::mifare::plus::AESKey& card_config_key = m5::nfc::a::mifare::plus::DEFAULT_KEY,
        const m5::nfc::a::mifare::plus::AESKey& card_master_key = m5::nfc::a::mifare::plus::DEFAULT_KEY,
        const m5::nfc::a::mifare::plus::AESKey& l2_switch_key   = m5::nfc::a::mifare::plus::DEFAULT_KEY,
        const m5::nfc::a::mifare::plus::AESKey& l3_switch_key   = m5::nfc::a::mifare::plus::DEFAULT_KEY,
        const m5::nfc::a::mifare::plus::AESKey& aes_sector_key  = m5::nfc::a::mifare::plus::DEFAULT_FF_KEY,
        const m5::nfc::a::mifare::classic::Key& key_a           = m5::nfc::a::mifare::classic::DEFAULT_KEY,
        const m5::nfc::a::mifare::classic::Key& key_b           = m5::nfc::a::mifare::classic::DEFAULT_KEY);
    /*!
      @brief Upgrade security level to SL2 (AES over CRYPTO1)
      @param sl2_switch_key SL2 Switch Key (AES)
      @return True if successful
      @warning This operation is irreversible
      @note Only supported on MIFARE Plus X / EV2
     */
    bool mifarePlusUpgradeSecurityLevel2(
        const m5::nfc::a::mifare::plus::AESKey& sl2_switch_key = m5::nfc::a::mifare::plus::DEFAULT_KEY);
    /*!
      @brief Upgrade security level to SL3 (AES)
      @param l3_switch_key Level 3 Switch Key (AES)
      @return True if successful
      @warning This operation is irreversible
      @note For Plus X/EV2, the PICC must be in SL2; otherwise SL1 is required
     */
    bool mifarePlusUpgradeSecurityLevel3(
        const m5::nfc::a::mifare::plus::AESKey& l3_switch_key = m5::nfc::a::mifare::plus::DEFAULT_KEY);

    ///@}

    ///@note For activated PICC
    ///@name For NDEF
    ///@{
    /*!
      @brief Is the PICC data in NDEF format?
      @param[out] valid True if NDEF format
      @return True if successful
     */
    bool ndefIsValidFormat(bool& valid);
    /*!
      @brief Prepare NDEF files on MIFARE DESFire Light
      @return True if successful
     */
    bool ndefPrepareDesfireLight();
    /*!
      @brief Prepare NDEF files on MIFARE DESFire (EV1/EV2/EV3)
      @param max_ndef_size Max size for NDEF file
      @return True if successful
     */
    bool ndefPrepareDesfire(const uint32_t max_ndef_size);
    /*!
      @brief Read NDEF Message TLV
      @param[out] msg Message If it does not exist, a Null TLV is returned
      @return True if successful
      @note If multiple messages of the same type exist, return the first one
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefRead(m5::nfc::ndef::TLV& msg);
    /*!
      @brief Read any NDEF TLV
      @param[out] tlvs Message vector
      @param tagBits Bit indicating the group of NDEF tags to be read
      @return True if successful
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefRead(std::vector<m5::nfc::ndef::TLV>& tlvs,
                  const m5::nfc::ndef::TagBits tagBits = m5::nfc::ndef::tagBitsAll);
    /*!
      @brief Write NDEF message
      @param msg Message (NDEF Message)
      @return True if successful
      @note Other existing tags will be preserved
      @warning Existing NDEF message TLVs will be overwritten
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const m5::nfc::ndef::TLV& msg);
    /*!
      @brief Write any NDEF Messages TLV
      @param tlvs Message vector
      @return True if successful
      @note Write starting from the beginning of the user area
      @warning Existing NDEF Message TLVs will be overwritten,
      @warning so exercise caution if Lock/Memory control is present
      @warning Only PICC cards supporting NDEF are valid
     */
    bool ndefWrite(const std::vector<m5::nfc::ndef::TLV>& tlvs);
    ///@}

protected:
    virtual bool read(uint8_t* rx, uint16_t& rx_len, const uint16_t saddr) override;
    virtual bool write(const uint16_t saddr, const uint8_t* tx, const uint16_t tx_len) override;
    inline virtual uint16_t first_user_block() const override
    {
        return _activePICC.firstUserBlock();
    }
    inline virtual uint16_t last_user_block() const override
    {
        return _activePICC.lastUserBlock();
    }
    inline virtual uint16_t user_area_size() const override
    {
        return _activePICC.userAreaSize();
    }
    inline virtual uint16_t unit_size_read() const override
    {
        return _activePICC.supportsNFC() ? (_activePICC.isMifareUltralight() ? 16 : 4) : 16;
    }
    inline virtual uint16_t unit_size_write() const override
    {
        return (_activePICC.supportsNFC()) ? 4 : 16;
    }

    bool identify_picc(m5::nfc::a::PICC& picc);
    m5::nfc::a::Type identify_picc_st25ta();
    uint8_t identify_plus_sl03();

    bool read_using_fast(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr);
    bool read_using_read16(uint8_t* rx, uint16_t& rx_len, const uint8_t saddr,
                           const m5::nfc::a::mifare::classic::Key& key);
    bool write_using_write4(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len);
    bool write_using_write16(const uint8_t addr, const uint8_t* tx, const uint16_t tx_len,
                             const m5::nfc::a::mifare::classic::Key& key);

    bool nfca_request_ats(m5::nfc::a::ATS& ats, const uint8_t fsdi = 5, const uint8_t cid = 0);
    bool nfca_deselect();

    bool mifare_get_version_L3(uint8_t ver[8]);
    bool mifare_get_version_L4_raw(uint8_t* ver, uint16_t& ver_len);
    bool mifare_get_version_L4_wrapped(uint8_t* ver, uint16_t& ver_len);

    bool mifare_plus_authenticateAES(const uint16_t key_no, const m5::nfc::a::mifare::plus::AESKey& key);
    bool mifare_plus_authenticateAES_L3(const uint16_t key_no, const m5::nfc::a::mifare::plus::AESKey& key);
    bool mifare_plus_read_plain_nomac(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out);
    bool mifare_plus_read_plain_mac(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out);
    bool mifare_plus_read_mac_l4(const uint16_t block, const uint8_t count, std::vector<uint8_t>& out,
                                 const bool plain);
    bool mifare_plus_write_mac_l4(const uint16_t block, const uint8_t* data, const uint16_t data_len, const bool plain);

    bool mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block, const uint32_t arg = 0);

    bool mifare_ultralightC_authenticate1(uint8_t ek[8]);
    bool mifare_ultralightC_authenticate2(uint8_t rx_ek[8], const uint8_t tx_ek[16]);

    bool ntag_read_page(uint8_t* rx, uint16_t& rx_len, const uint8_t spage, const uint8_t epage);
    bool ntag_write_page(const uint8_t page, const uint8_t tx[4]);  // NTAG,UL,ULC

    bool dump_sector_structure(const m5::nfc::a::PICC& picc, const m5::nfc::a::mifare::classic::Key& key);
    bool dump_sector(const uint8_t sector);
    bool dump_sector_mifare_plus_sl3(const uint8_t sector);
    bool dump_page_structure(const uint16_t maxPage);
    bool dump_page(const uint8_t page, const uint16_t maxPage);
    bool dump_mifare_plus_sl3(const m5::nfc::a::mifare::plus::AESKey& key);
    bool dump_desfire();
    bool dump_desfire_light();
    bool dump_st25ta();

    static bool push_back_picc(std::vector<m5::nfc::a::PICC>& v, const m5::nfc::a::PICC& picc);

protected:
    m5::nfc::a::PICC _activePICC{};
    m5::nfc::a::config_t _cfg{};
    m5::nfc::ndef::NDEFLayer _ndef;
    m5::nfc::isodep::IsoDEP _isoDEP;

private:
    bool mifare_plus_transceive_raw(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len);

    // Session state for MIFARE Plus
    struct MifarePlusSession {
        bool authenticated{};
        uint16_t key_no{};
        uint16_t r_ctr{};
        uint16_t w_ctr{};
        uint8_t frame_num{};
        std::array<uint8_t, 4> ti{};
        std::array<uint8_t, 16> kenc{};
        std::array<uint8_t, 16> kmac{};
    };

    MifarePlusSession _mfp_session{};
    std::unique_ptr<Adapter> _impl;
};

/*!
  @struct NFCLayerA::Adapter
  @brief Chip interface for NFC-A
  @note Implement this to drive a chip this library does not know about, then hand it to
  NFCLayerA(std::unique_ptr<Adapter>)
  @warning A chip that keeps a MIFARE Classic cipher session alive has to end it in hlt(),
  request() or wakeup(). NFCLayerA::deactivate() calls hlt() for a MIFARE Classic compatible PICC,
  so the layer already gives the adapter that chance
 */
struct NFCLayerA::Adapter {
    virtual ~Adapter() = default;

    /*!
      @brief Maximum FIFO depth in bytes
      @return Maximum FIFO depth in bytes
      @note Answers NFCLayerA::maximum_fifo_depth(), which spells the same thing in full
     */
    virtual uint16_t max_fifo_depth() const = 0;

    /*!
      @brief Send a frame and wait for the answer
      @param[out] rx Receive buffer
      @param[in,out] rx_len In: capacity of rx, Out: received length
      @param tx Transmit buffer
      @param tx_len Transmit length
      @param timeout_ms Timeout in milliseconds
      @return True if an answer came back
      @note The layer hands over frames without a CRC_A, so the chip has to add it
      @warning The answer is expected to still carry its CRC_A, and rx_len caps how much of it is
      kept. Callers that want the CRC read into a buffer large enough for it; callers that do not
      pass a buffer that ends where the payload does, which drops the CRC on the floor. A chip that
      strips the CRC itself has to put it back, or ISO-DEP breaks: it takes two bytes off every
      answer (see isoDEP.hpp rx_crc)
      @note REQA and WUPA are the exception and come back without a CRC_A
      @note RATS and S(DESELECT) go out this way, so the chip must not answer them on its own
     */
    virtual bool transceive(uint8_t* rx, uint16_t& rx_len, const uint8_t* tx, const uint16_t tx_len,
                            const uint32_t timeout_ms) = 0;

    /*!
      @brief Look for a PICC that is not halted (REQA)
      @param[out] atqa ATQA the PICC answered with
      @return True if a PICC answered
     */
    virtual bool request(uint16_t& atqa) = 0;
    /*!
      @brief Look for a PICC whether or not it is halted (WUPA)
      @param[out] atqa ATQA the PICC answered with
      @return True if a PICC answered
     */
    virtual bool wakeup(uint16_t& atqa) = 0;

    /*!
      @brief Run anticollision and select the PICC it settles on
      @param[out] picc PICC that was selected, filled in with its ATQA, SAK and UID
      @return True if a PICC was selected
      @note The layer asks for the ATS itself when the PICC turns out to be ISO14443-4, so the chip
      must not send RATS here
      @warning This is the only place the ATQA can be put into the PICC. The layer never fills it
      in anywhere else, and activate() takes the PICC by const reference, so whatever this leaves
      in picc.atqa is what the rest of the library works with. A chip that learns the ATQA in
      request() has to carry it through, one that learns it here has to write it
      @note The ATQA is read again after activation to tell MIFARE Plus 2K from 4K, so leaving it
      at zero misidentifies those cards
     */
    virtual bool select(m5::nfc::a::PICC& picc) = 0;
    /*!
      @brief Select a PICC by its UID, waking it if it is halted
      @param picc PICC to select
      @return True if the PICC was selected
      @note As with select(), the layer sends RATS itself
     */
    virtual bool activate(const m5::nfc::a::PICC& picc) = 0;
    /*!
      @brief Put the selected PICC to sleep (HLTA)
      @return True if successful
      @note A PICC answers nothing to HLTA, so silence is the expected outcome
      @note This is where a chip ends a MIFARE Classic cipher session, see the warning on this
      struct
     */
    virtual bool hlt() = 0;

    /*!
      @brief Read one 16 byte block
      @param[out] rx Receive buffer
      @param addr Block address
      @return True if successful
      @note Named after NFC-A rather than the block size because MIFARE Classic and Ultralight
      answer READ with 16 bytes alike
     */
    virtual bool nfca_read_block(uint8_t rx[16], const uint8_t addr) = 0;
    /*!
      @brief Write one 16 byte block
      @param addr Block address
      @param tx Data to write
      @return True if successful
     */
    virtual bool nfca_write_block(const uint8_t addr, const uint8_t tx[16]) = 0;
    /*!
      @brief Authenticate a MIFARE Classic sector
      @param auth_a True to authenticate with key A, false for key B
      @param picc PICC to authenticate against, needed for its UID
      @param block Block address in the sector to authenticate
      @param key Six byte key
      @return True if the PICC accepted the key
      @note A chip that runs Crypto1 in hardware keeps the session open until hlt(), request() or
      wakeup(), see the warning on this struct
     */
    virtual bool mifare_classic_authenticate(const bool auth_a, const m5::nfc::a::PICC& picc, const uint8_t block,
                                             const m5::nfc::a::mifare::classic::Key& key) = 0;
    /*!
      @brief Run a MIFARE Classic value block command
      @param cmd INCREMENT, DECREMENT, RESTORE or TRANSFER
      @param block Block address
      @param arg Operand for INCREMENT and DECREMENT, ignored by RESTORE and TRANSFER
      @return True if successful
      @note INCREMENT, DECREMENT and RESTORE only load the internal register; TRANSFER is what
      writes it back
     */
    virtual bool mifare_classic_value_block(const m5::nfc::a::Command cmd, const uint8_t block,
                                            const uint32_t arg = 0) = 0;
};

}  // namespace nfc
}  // namespace m5

#endif
