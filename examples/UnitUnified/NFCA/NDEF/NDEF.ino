/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
  Read/write NDEF NFC-A PICC
  This example is shared with M5Unit-RFID
*/
// *************************************************************
// Choose ONE define symbol to match the unit/board you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101) && !defined(USING_UNIT_RFID2) && \
    !defined(USING_M5DIAL_BUILTIN_WS1850S)
// For UnitNFC (U216)
// #define USING_UNIT_NFC
// For CapCC1101 (U219)
// #define USING_CAP_CC1101
// For UnitRFID2 (U031-B)
// #define USING_UNIT_RFID2
// For M5Dial Builtin WS1850S (K130)
// #define USING_M5DIAL_BUILTIN_WS1850S
#endif
#include "main/NDEF.cpp"
