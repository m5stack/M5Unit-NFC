/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for ST25R3916
  Read/Write with MAC example for FeliCa Lite-S

  *******************************************************************************************************************
  NOTICE: Please note that cards that have undergone the initial issuance procedure cannot be read without subsequent
  authentication.
  *******************************************************************************************************************
*/
// *************************************************************
// Choose one define symbol to match the unit you are using
// *************************************************************
#if !defined(USING_UNIT_NFC) && !defined(USING_HACKER_CAP)
// For UnitNFC
// #define USING_UNIT_NFC
// For CapNFC
// #define USING_HACKER_CAP
#endif
#include "main/ReadWriteMAC.cpp"
