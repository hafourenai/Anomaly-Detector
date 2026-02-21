#include "config.h"
#include "secrets.h"

#include "src/network/NetworkScanner.h"
#include "src/network/EvilTwinDetector.h"
#include "src/attack/DeauthDetector.h"
#include "src/attack/PromiscuousMonitor.h"
#include "src/alerts/AlertManager.h"
#include "src/alerts/TelegramNotifier.h"
#if ENABLE_OLED
#include "src/display/DisplayManager.h"
#endif
#include "src/web/WebServerHandler.h"
#include "src/storage/StorageManager.h"
#include "src/network/WiFiManager.h"

#include <ArduinoOTA.h>

NetworkScanner     networkScanner;
EvilTwinDetector   evilTwinDetector;
DeauthDetector     deauthDetector;
PromiscuousMonitor promiscuousMonitor;
AlertManager       alertManager;
TelegramNotifier   telegramNotifier(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID);
#if ENABLE_OLED
DisplayManager     displayManager;
#endif
WebServerHandler   webServer;
StorageManager     storage;
WiFiManager        wifiManager;

bool _webServerStarted  = false;
bool _telegramStarted   = false;

static unsigned long lastHeapReport     = 0;
static unsigned long lastHeapAlertSent  = 0;
#define HEAP_REPORT_INTERVAL_MS  60000UL   
#define HEAP_CRITICAL_BYTES      4000      
#define HEAP_ALERT_INTERVAL_MS   300000UL  

void onWiFiReconnected();
void startNetworkServices();
void setupOTA();
void checkHeapHealth();

void setup() {
  Serial.begin(115200);
  Serial.println("\n=== A-Dect ===");

  ESP.wdtDisable();
  ESP.wdtEnable(8000);  

  if (!storage.begin()) {
    Serial.println("[FATAL] Storage gagal! Check LittleFS.");
  }

#if ENABLE_OLED
  displayManager.begin();
  displayManager.showBootScreen();
#endif

  IPAddress local_ip(192, 168, 1, 200);
  IPAddress gateway(192, 168, 1, 1);
  IPAddress subnet(255, 255, 255, 0);
  IPAddress dns1(8, 8, 8, 8);
  IPAddress dns2(8, 8, 4, 4);

  wifiManager.setReconnectCallback(onWiFiReconnected);

  bool connected = wifiManager.begin(WIFI_SSID, WIFI_PASSWORD,
                                     local_ip, gateway, subnet, dns1, dns2);

  if (connected) {
    startNetworkServices();
  } else {
    Serial.println("[OFFLINE] Monitoring lokal aktif. Retry WiFi di background.");
  }

  evilTwinDetector.loadTrustedAPs(storage);
  promiscuousMonitor.begin(&deauthDetector);

#if ENABLE_OLED
  if (!connected) {
    displayManager.showReady("OFFLINE");
  } else {
    displayManager.showReady(WiFi.localIP().toString());
  }
#endif

  Serial.println("[OK] A-Dect siap.");
}

void loop() {
  static unsigned long lastScanTime      = 0;
  static unsigned long lastDisplayUpdate = 0;
  static unsigned long lastTelegramSent  = 0;
  static AlertType     lastTelegramType  = ALERT_NONE;
  unsigned long currentTime = millis();

  wifiManager.update();

  if (_webServerStarted) {
    ArduinoOTA.handle();
  }

  if (currentTime - lastScanTime > SCAN_INTERVAL) {
    networkScanner.scan();
    lastScanTime = currentTime;
  }

  if (networkScanner.isScanComplete()) {
    networkScanner.processScanResults();
    evilTwinDetector.checkForEvilTwins(networkScanner.getResults());
  }

  if (evilTwinDetector.isEvilTwinDetected()) {
    char msgBuf[160];
    snprintf(msgBuf, sizeof(msgBuf),
             "*EVIL TWIN DETECTED!*\n\nSSID: %s\nFake BSSID: %s",
             evilTwinDetector.getEvilTwinSSID().c_str(),
             evilTwinDetector.getEvilTwinBSSID().c_str());
    char detailBuf[48];
    snprintf(detailBuf, sizeof(detailBuf),
             "SSID: %s", evilTwinDetector.getEvilTwinSSID().c_str());
    alertManager.setAlert(ALERT_EVIL_TWIN, String(msgBuf), String(detailBuf));
  }

  deauthDetector.update();
  if (deauthDetector.isAttackDetected()) {
    int frameCount = deauthDetector.getActiveAlertCount();
    char msgBuf[128];
    snprintf(msgBuf, sizeof(msgBuf),
             "DEAUTH ATTACK DETECTED!\n\nFrames: %d\nWindow: 10s", frameCount);
    char detailBuf[32];
    snprintf(detailBuf, sizeof(detailBuf), "Deauth frames: %d", frameCount);
    alertManager.setAlert(ALERT_DEAUTH, String(msgBuf), String(detailBuf));
  }
  alertManager.update();
  if (!alertManager.hasActiveAlert() && evilTwinDetector.isEvilTwinDetected()) {
    evilTwinDetector.clearAlert();
  }
  if (alertManager.hasActiveAlert() && !alertManager.isAlertSent()) {
    bool rateLimitOk = !(lastTelegramType == alertManager.getAlertType() &&
                         (currentTime - lastTelegramSent) < 60000UL);

    if (rateLimitOk && wifiManager.isConnected()) {
      telegramNotifier.sendAlert(alertManager.getAlertMessage());
      lastTelegramSent = currentTime;
      lastTelegramType = alertManager.getAlertType();
    }
    alertManager.markAlertSent();
  }

  if (wifiManager.isConnected()) {
    telegramNotifier.process();
  }
  checkHeapHealth();

#if ENABLE_OLED
  if (currentTime - lastDisplayUpdate > DISPLAY_UPDATE_INTERVAL) {
    if (alertManager.hasActiveAlert()) {
      displayManager.showAlert(alertManager.getAlertType(), alertManager.getAlertDetails());
    } else {
      displayManager.showNormal(networkScanner.getNetworkCount(),
                                deauthDetector.getActiveAlertCount());
    }
    lastDisplayUpdate = currentTime;
  }
#endif

  yield();
}

void startNetworkServices() {
  if (!_webServerStarted) {
    webServer.setStatusCallback([&](JsonObject& json) {
      json["attackDetected"]     = alertManager.hasActiveAlert();
      json["attackType"]         = alertManager.getAlertTypeString();
      json["attackDetails"]      = alertManager.getAlertDetails();
      json["networkCount"]       = networkScanner.getNetworkCount();
      json["alertCount"]         = deauthDetector.getActiveAlertCount();
      json["uptime"]             = millis() / 1000;
      json["freeHeap"]           = ESP.getFreeHeap();
      json["reconnectAttempts"]  = wifiManager.getReconnectAttempts();
      json["wifiConnected"]      = wifiManager.isConnected();

      JsonArray aps = json.createNestedArray("aps");
      auto& networks = networkScanner.getResults();
      for (auto& net : networks) {
        JsonObject ap = aps.createNestedObject();
        ap["ssid"] = net.ssid;
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 net.bssid[0], net.bssid[1], net.bssid[2],
                 net.bssid[3], net.bssid[4], net.bssid[5]);
        ap["bssid"]   = String(mac);
        ap["rssi"]    = net.rssi;
        ap["trusted"] = evilTwinDetector.getTrustedAPManager().isTrusted(net.ssid);
      }
    });

    webServer.setAddNetworkCallback([&](String ssid, String bssid) {
      ssid.trim();
      bssid.trim();

      if (ssid.length() == 0 || ssid.length() > 32) {
        Serial.println("[ERROR] SSID tidak valid");
        return;
      }

      uint8_t mac[6] = {0};
      if (bssid.length() > 0) {
        int vals[6];
        int parsed = sscanf(bssid.c_str(), "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
        if (parsed != 6) {
          #ifdef ENABLE_SERIAL_DEBUG
          char errBuf[64];
          snprintf(errBuf, sizeof(errBuf), "[ERROR] Malformed BSSID rejected: %s", bssid.c_str());
          Serial.println(errBuf);
          #endif
          return;
        }
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)vals[i];
      }

      evilTwinDetector.getTrustedAPManager().addTrustedAP(ssid, mac);
      evilTwinDetector.getTrustedAPManager().saveToStorage(storage);
    });

    webServer.begin();
    _webServerStarted = true;
    Serial.println("[OK] Web server dimulai");
  }

  if (!_telegramStarted) {
    telegramNotifier.begin();
    _telegramStarted = true;
  }

  setupOTA();
}

void onWiFiReconnected() {
  Serial.println("[WiFi] Koneksi pulih — re-inisialisasi layanan...");

  _telegramStarted = false;

  startNetworkServices();
  char msg[128];
  snprintf(msg, sizeof(msg),
           "*A-Dect Online*\n\nKoneksi pulih setelah %lu menit offline.",
           wifiManager.getDisconnectedDuration() / 60000UL);
  telegramNotifier.sendAlert(String(msg));

#if ENABLE_OLED
  displayManager.showReady(WiFi.localIP().toString());
#endif
}

void setupOTA() {
  ArduinoOTA.setHostname("A-Dect");

  ArduinoOTA.setPassword(OTA_PASSWORD);

  ArduinoOTA.onStart([]() {
    Serial.println("[OTA] Update dimulai...");
  });

  ArduinoOTA.onEnd([]() {
    Serial.println("\n[OTA] Selesai — restart");
  });

  ArduinoOTA.onError([](ota_error_t error) {
    Serial.print("[OTA] Error: ");
    Serial.println(error);
  });

  ArduinoOTA.begin();
  Serial.println("[OK] OTA siap di port 8266");
}

void checkHeapHealth() {
  unsigned long now = millis();
  if (now - lastHeapReport < HEAP_REPORT_INTERVAL_MS) return;
  lastHeapReport = now;

  uint32_t freeHeap = ESP.getFreeHeap();

  #ifdef ENABLE_SERIAL_DEBUG
  Serial.print("[Heap] Free: ");
  Serial.print(freeHeap);
  Serial.println(" bytes");
  #endif

  if (freeHeap < HEAP_CRITICAL_BYTES &&
      (now - lastHeapAlertSent) > HEAP_ALERT_INTERVAL_MS &&
      wifiManager.isConnected()) {

    char msg[128];
    snprintf(msg, sizeof(msg),
             "*Heap Kritis!*\n\nFree heap: %u bytes\nUptime: %lu menit",
             freeHeap, now / 60000UL);
    telegramNotifier.sendAlert(String(msg));
    lastHeapAlertSent = now;
  }
}
