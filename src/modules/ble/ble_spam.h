#ifndef BLE_SPAM_H
#define BLE_SPAM_H

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>

enum EBLEPayloadType { Microsoft, SourApple, AppleJuice, Samsung, Google };

void generateRandomMac(uint8_t *mac);
void executeSpam(EBLEPayloadType type, String customName = "");
void executeCustomSpam(String spamName);
void ibeacon(const char *DeviceName, const char *BEACON_UUID, int ManufacturerId);
void aj_adv(int ble_choice);
void legacySubMenu();
void spamMenu();

// Legacy Apple spam state machine
void startLegacyAppleSpam(EBLEPayloadType type);
void stopLegacyAppleSpam();
bool isLegacyAppleSpamRunning();
void updateLegacyAppleSpam();

// Samsung spam state machine
void startSamsungSpam();
void stopSamsungSpam();
bool isSamsungSpamRunning();
void updateSamsungSpam();

// Google FastPair spam state machine
void startGoogleSpam();
void stopGoogleSpam();
bool isGoogleSpamRunning();
void updateGoogleSpam();

// Windows SwiftPair spam state machine
void startWindowsSpam();
void stopWindowsSpam();
bool isWindowsSpamRunning();
void updateWindowsSpam();

#endif
