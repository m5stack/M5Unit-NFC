/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for M5Unit-NFC/RFID
  Detect NFC-A PICC
  This example is shared with M5Unit-RFID
*/
// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_CAP_CC1101) && !defined(USING_UNIT_RFID2)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_CAP_CC1101
// For UnitRFID2
// #define USING_UNIT_RFID2
#endif
#include "main/Detect.cpp"
